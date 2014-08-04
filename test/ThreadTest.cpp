/*
 * Copyright (C) 2004-2014 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <znc/Threads.h>

class CWaitingJob : public CJob {
public:
	CWaitingJob(bool& destroyed)
		: m_bDestroyed(destroyed), m_Mutex(), m_CV(), m_bThreadReady(false), m_bThreadDone(false) {
	};


	~CWaitingJob() {
		m_bDestroyed = true;
	}

	void signal() {
		CMutexLocker locker(m_Mutex);
		// Wait for the thread to run
		while (!m_bThreadReady)
			m_CV.wait(m_Mutex);

		// and signal it to exit
		m_bThreadDone = true;
		m_CV.broadcast();
	}

	virtual void runThread() {
		CMutexLocker locker(m_Mutex);
		// We are running
		m_bThreadReady = true;
		m_CV.broadcast();

		// wait for our exit signal
		while (!m_bThreadDone)
			m_CV.wait(m_Mutex);
	}

	virtual void runMain() {
		assert(m_bThreadReady == true);
		assert(m_bThreadDone == true);
		assert(!wasCancelled());
	}

private:
	bool& m_bDestroyed;
	CMutex m_Mutex;
	CConditionVariable m_CV;
	bool m_bThreadReady;
	bool m_bThreadDone;
};

TEST(Thread, RunJob) {
	bool destroyed = false;
	CWaitingJob *pJob = new CWaitingJob(destroyed);

	CThreadPool::Get().addJob(pJob);
	pJob->signal();

	while (!destroyed)
		CThreadPool::Get().handlePipeReadable();
}

class CCancelJob : public CJob {
public:
	CCancelJob(bool& destroyed)
		: m_bDestroyed(destroyed), m_Mutex(), m_CV(), m_bThreadReady(false) {
	}

	~CCancelJob() {
		m_bDestroyed = true;
	}

	void wait() {
		CMutexLocker locker(m_Mutex);
		// Wait for the thread to run
		while (!m_bThreadReady)
			m_CV.wait(m_Mutex);
	}

	virtual void runThread() {
		CMutexLocker locker(m_Mutex);
		// We are running
		m_bThreadReady = true;
		m_CV.broadcast();
		locker.unlock();

		while (!wasCancelled()) {
		}
	}

	virtual void runMain() {
		assert(m_bThreadReady == true);
		assert(wasCancelled());
	}

private:
	bool& m_bDestroyed;
	CMutex m_Mutex;
	CConditionVariable m_CV;
	bool m_bThreadReady;
};

TEST(Thread, CancelJobEarly) {
	bool destroyed = false;
	CCancelJob *pJob = new CCancelJob(destroyed);

	CThreadPool::Get().addJob(pJob);
	// Don't wait for the job to run
	CThreadPool::Get().cancelJob(pJob);

	while (!destroyed)
		CThreadPool::Get().handlePipeReadable();
}

TEST(Thread, CancelJobWhileRunning) {
	bool destroyed = false;
	CCancelJob *pJob = new CCancelJob(destroyed);

	CThreadPool::Get().addJob(pJob);
	// Wait for the job to run
	pJob->wait();
	CThreadPool::Get().cancelJob(pJob);

	while (!destroyed)
		CThreadPool::Get().handlePipeReadable();
}

class CEmptyJob : public CJob {
public:
	CEmptyJob(bool& destroyed)
		: m_bDestroyed(destroyed) {
	}

	~CEmptyJob() {
		m_bDestroyed = true;
	}

	void wait() {
		CMutexLocker locker(m_Mutex);
		// Wait for the thread to run
		while (!m_bThreadReady)
			m_CV.wait(m_Mutex);
	}

	virtual void runThread() {
		CMutexLocker locker(m_Mutex);
		// We are running
		m_bThreadReady = true;
		m_CV.broadcast();
	}

	virtual void runMain() {
		assert(!wasCancelled());
	}

private:
	bool& m_bDestroyed;
	CMutex m_Mutex;
	CConditionVariable m_CV;
	bool m_bThreadReady;
};

TEST(Thread, CancelJobWhenDone) {
	bool destroyed = false;
	CEmptyJob *pJob = new CEmptyJob(destroyed);

	CThreadPool::Get().addJob(pJob);
	// Wait for the job to finish
	pJob->wait();
	CThreadPool::Get().cancelJob(pJob);

	while (!destroyed)
		CThreadPool::Get().handlePipeReadable();
}
