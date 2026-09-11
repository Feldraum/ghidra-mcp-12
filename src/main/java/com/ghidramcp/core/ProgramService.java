/* ###
 * GhidraMCP12 - Model Context Protocol bridge for Ghidra
 */
package com.ghidramcp.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Single, thread-safe gateway to "the program the bridge is talking to".
 *
 * <p>The bridge serves requests on HTTP worker threads while Ghidra mutates
 * programs on the Swing thread (GUI mode) or on the analysis thread (headless
 * mode). Every operation therefore funnels through here:
 *
 * <ul>
 *   <li>read operations run under {@link #read}, which holds a per-program lock
 *       so the bridge's own index and deserialisation code cannot race its own
 *       writes;</li>
 *   <li>mutations run under {@link #mutate}, which dispatches to the Swing thread
 *       and always wraps the work in a Ghidra transaction.</li>
 * </ul>
 */
public final class ProgramService {

	private final PluginTool tool;

	/** Per-program locks so that two open programs do not serialise each other. */
	private static final class Locks {
		private static final Map<Program, ReentrantLock> LOCKS =
			Collections.synchronizedMap(new WeakHashMap<>());

		static ReentrantLock forProgram(Program program) {
			synchronized (LOCKS) {
				return LOCKS.computeIfAbsent(program, p -> new ReentrantLock(true));
			}
		}
	}

	public ProgramService(PluginTool tool) {
		if (tool == null) {
			throw new IllegalArgumentException(
				"ProgramService needs a PluginTool; the bridge is a GUI plugin");
		}
		this.tool = tool;
	}

	/** The program requests operate on, or {@code null} when none is open. */
	public Program current() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		return pm == null ? null : pm.getCurrentProgram();
	}

	/** Every program currently open in the tool. */
	public List<Program> allOpen() {
		List<Program> out = new ArrayList<>();
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			for (Program p : pm.getAllOpenPrograms()) {
				out.add(p);
			}
		}
		return out;
	}

	/**
	 * Selects an open program as current, so an agent working with several
	 * programs open can say which one it means.
	 *
	 * @throws IllegalArgumentException if no open program has that name
	 */
	public Program activate(String name) {
		if (name == null || name.isBlank()) {
			return current();
		}
		for (Program p : allOpen()) {
			if (p.getName().equals(name) || p.getName().startsWith(name)) {
				ProgramManager pm = tool.getService(ProgramManager.class);
				if (pm != null) {
					pm.setCurrentProgram(p);
				}
				return p;
			}
		}
		throw new IllegalArgumentException("no open program named '" + name + "'");
	}

	/** Opens a program from the active project into the tool and makes it current. */
	public Program openFromProject(String pathInProject, boolean readOnly) throws Exception {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm == null) {
			throw new IllegalStateException("ProgramManager service is unavailable");
		}
		ghidra.framework.model.Project project = tool.getProject();
		if (project == null) {
			throw new IllegalStateException("no project is open");
		}
		String p = pathInProject.startsWith("/") ? pathInProject : "/" + pathInProject;
		ghidra.framework.model.DomainFile df = project.getProjectData().getFile(p);
		if (df == null) {
			throw new IllegalArgumentException("no file at project path " + p);
		}
		Object consumer = this;
		DomainObject dobj = df.getDomainObject(consumer, false, false, monitor());
		if (!(dobj instanceof Program program)) {
			dobj.release(consumer);
			throw new IllegalArgumentException(p + " is not a Program");
		}
		pm.openProgram(program);
		return program;
	}

	/** Monitor to use for long running operations. */
	private TaskMonitor monitor() {
		return TaskMonitor.DUMMY;
	}

	/**
	 * Runs a read-only operation while holding the program's bridge lock.
	 *
	 * <p>Ghidra's {@code DomainObject} has no consumer lock to take
	 * ({@code lock()}/{@code unlock()} take the on-disk project lock), so the
	 * bridge keeps its own lock to serialise its own reads against its own
	 * writes. Ghidra's database is safe for concurrent readers in the GUI, but
	 * the index/deserialisation code in this bridge is not, and serialising here
	 * makes the whole bridge's behaviour predictable.
	 *
	 * @throws IllegalStateException when no program is open
	 */
	public <T> T read(Callable<T> work) {
		Program program = current();
		if (program == null) {
			throw new IllegalStateException(
				"No program is open. Open a program in Ghidra, then retry.");
		}
		ReentrantLock lock = Locks.forProgram(program);
		lock.lock();
		try {
			return work.call();
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Runs a mutating operation inside a Ghidra transaction, on the Swing thread.
	 *
	 * <p>Dispatching to the EDT is not optional: Ghidra's undo manager and many
	 * model listeners assume it, and doing otherwise produces intermittent
	 * {@code ConcurrentModificationException}s inside Ghidra itself.
	 *
	 * @return the value produced by {@code work}
	 */
	public <T> T mutate(String transactionName, Callable<T> work) {
		Program program = current();
		if (program == null) {
			throw new IllegalStateException("No program is open; cannot modify anything.");
		}
		if (!program.isChangeable()) {
			throw new IllegalStateException(
				"The program is read-only (opened without write access); modifications are not possible.");
		}

		Callable<T> guarded = () -> {
			int tx = program.startTransaction(transactionName);
			boolean commit = false;
			try {
				T result = work.call();
				commit = true;
				return result;
			}
			finally {
				program.endTransaction(tx, commit);
				// Any decompiler state held for this program is now stale.
				Decompiler.invalidate(program);
			}
		};
		return onSwingThread(guarded);
	}

	private <T> T onSwingThread(Callable<T> work) {
		if (javax.swing.SwingUtilities.isEventDispatchThread()) {
			// Already on the EDT: run inline. Going through invokeAndWait here
			// would deadlock.
			return workNow(work);
		}
		AtomicReference<T> result = new AtomicReference<>();
		AtomicReference<Throwable> failure = new AtomicReference<>();
		try {
			javax.swing.SwingUtilities.invokeAndWait(() -> {
				try {
					result.set(work.call());
				}
				catch (Throwable t) {
					failure.set(t);
				}
			});
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException("interrupted while waiting for the Ghidra UI thread", e);
		}
		catch (java.lang.reflect.InvocationTargetException e) {
			failure.set(e.getCause() == null ? e : e.getCause());
		}
		Throwable t = failure.get();
		if (t != null) {
			if (t instanceof RuntimeException re) {
				throw re;
			}
			if (t instanceof Error err) {
				throw err;
			}
			throw new IllegalStateException(t.getMessage(), t);
		}
		return result.get();
	}

	/**
	 * Runs {@code work} on the calling thread and translates its checked
	 * exceptions, for the case where the caller is already on the EDT.
	 */
	private <T> T workNow(Callable<T> work) {
		try {
			return work.call();
		}
		catch (RuntimeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IllegalStateException(e.getMessage(), e);
		}
	}
}
