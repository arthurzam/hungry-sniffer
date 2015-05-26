// http://gnodebian.blogspot.com.es/2013/07/a-thread-safe-asynchronous-queue-in-c11.html
#ifndef _SafeQueue
#define _SafeQueue

#include <queue>
#include <list>
#include <mutex>
#include <thread>
#include <cstdint>
#include <condition_variable>

/**
 * @brief A thread-safe asynchronous queue
 */
template <class T, class Container = std::list<T>>
class SafeQueue
{
        typedef typename Container::value_type value_type;
        typedef typename Container::size_type size_type;
        typedef Container container_type;

    public:
        /*! Create safe queue. */
        SafeQueue() = default;
        SafeQueue (SafeQueue&& sq)
        {
            m_queue = std::move (sq.m_queue);
        }
        SafeQueue (const SafeQueue& sq)
        {
            std::lock_guard<std::mutex> lock (sq.m_mutex);
            m_queue = sq.m_queue;
        }

        /*! Destroy safe queue. */
        ~SafeQueue()
        {
            std::lock_guard<std::mutex> lock (m_mutex);
        }

        /**
         * @brief Sets the maximum number of items in the queue. Defaults is 0: No limit
         *
         * @param max_num_items maximum number
         */
        void set_max_num_items (unsigned int max_num_items)
        {
            m_max_num_items = max_num_items;
        }

        /**
         * @brief Pushes the item into the queue.
         *
         * @param item An item.
         * @return true if an item was pushed into the queue
         */
        bool push (const value_type& item)
        {
            std::lock_guard<std::mutex> lock (m_mutex);

            if (m_max_num_items > 0 && m_queue.size() > m_max_num_items)
                return false;

            m_queue.push (item);
            m_condition.notify_one();
            return true;
        }

        /**
         * @brief Pushes the item into the queue.
         *
         * @param item An item.
         * @return true if an item was pushed into the queue
         */
        bool push (value_type&& item)
        {
            std::lock_guard<std::mutex> lock (m_mutex);

            if (m_max_num_items > 0 && m_queue.size() > m_max_num_items)
                return false;

            m_queue.push (std::move(item));
            m_condition.notify_one();
            return true;
        }

        /**
         * @brief Pops item from the queue.
         *
         * If queue is empty, this function blocks until item becomes available.
         * @param item The item.
         */
        void pop (value_type& item)
        {
            std::unique_lock<std::mutex> lock (m_mutex);
            m_condition.wait (lock, [this]() // Lambda funct
            {
                                  return !m_queue.empty();
                              });
            item = m_queue.front();
            m_queue.pop();
        }

        /**
         * @brief Pops item from the queue and moves into item.
         *
         * Pops item from the queue using the contained type's move assignment operator, if it has one.
         * This method is identical to the pop() method if that type has no move assignment operator.
         * If queue is empty, this function blocks until item becomes available.
         * @param item The item.
         */
        void move_pop (value_type& item)
        {
            std::unique_lock<std::mutex> lock (m_mutex);
            m_condition.wait (lock, [this]() // Lambda funct
            {
                                  return !m_queue.empty();
                              });
            item = std::move (m_queue.front());
            m_queue.pop();
        }

        /**
         * @brief Tries to pop item from the queue.
         * @param item The item.
         * @return False is returned if no item is available.
         */
        bool try_pop (value_type& item)
        {
            std::unique_lock<std::mutex> lock (m_mutex);

            if (m_queue.empty())
                return false;

            item = m_queue.front();
            m_queue.pop();
            return true;
        }

        /**
         * @brief Tries to pop item from the queue and moves into item.
         *
         * Tries to pop item from the queue using the contained type's move assignment operator, if it has one.
         * This method is identical to the try_pop() method if that type has no move assignment operator.
         * @param item The item.
         * @return False is returned if no item is available.
         */
        bool try_move_pop (value_type& item)
        {
            std::unique_lock<std::mutex> lock (m_mutex);

            if (m_queue.empty())
                return false;

            item = std::move (m_queue.front());
            m_queue.pop();
            return true;
        }

        /**
         * @brief Tries to pop item from the queue.
         *
         * Pops item from the queue. If the queue is empty, blocks for timeout milliseconds, or until item becomes available.
         * @param item The item.
         * @param timeout The number of milliseconds to wait.
         * @return true if get an item from the queue, false if no item is received before the timeout.
         */
        bool timeout_pop (value_type& item, std::uint64_t timeout)
        {
            std::unique_lock<std::mutex> lock (m_mutex);

            if (m_queue.empty())
            {
                if (timeout == 0)
                    return false;

                if (m_condition.wait_for (lock, std::chrono::milliseconds (timeout)) == std::cv_status::timeout)
                    return false;
            }

            item = m_queue.front();
            m_queue.pop();
            return true;
        }

        /**
         *  Pops item from the queue using the contained type's move assignment operator, if it has one..
         *  If the queue is empty, blocks for timeout milliseconds, or until item becomes available.
         *  This method is identical to the try_pop() method if that type has no move assignment operator.
         * @param item The item.
         * @param timeout The number of milliseconds to wait.
         * @return true if get an item from the queue, false if no item is received before the timeout.
         */
        bool timeout_move_pop (value_type& item, std::uint64_t timeout)
        {
            std::unique_lock<std::mutex> lock (m_mutex);

            if (m_queue.empty())
            {
                if (timeout == 0)
                    return false;

                if (m_condition.wait_for (lock, std::chrono::milliseconds (timeout)) == std::cv_status::timeout)
                    return false;
            }

            item = std::move (m_queue.front());
            m_queue.pop();
            return true;
        }

        /**
         * @brief Gets the number of items in the queue.
         *
         * @return Number of items in the queue.
         */
        size_type size() const
        {
            std::lock_guard<std::mutex> lock (m_mutex);
            return m_queue.size();
        }

        /**
         * @brief Check if the queue is empty.
         *
         * @return true if queue is empty.
         */
        bool empty() const
        {
            std::lock_guard<std::mutex> lock (m_mutex);
            return m_queue.empty();
        }

        /**
         * @brief Swaps the contents.
         *
         * @param sq The SafeQueue to swap with 'this'.
         */
        void swap (SafeQueue& sq)
        {
            if (this != &sq)
            {
                std::lock_guard<std::mutex> lock1 (m_mutex);
                std::lock_guard<std::mutex> lock2 (sq.m_mutex);
                m_queue.swap (sq.m_queue);

                if (!m_queue.empty())
                    m_condition.notify_all();

                if (!sq.m_queue.empty())
                    sq.m_condition.notify_all();
            }
        }

        /*! The copy assignment operator */
        SafeQueue& operator= (const SafeQueue& sq)
        {
            if (this != &sq)
            {
                std::lock_guard<std::mutex> lock1 (m_mutex);
                std::lock_guard<std::mutex> lock2 (sq.m_mutex);
                std::queue<T, Container> temp {sq.m_queue};
                m_queue.swap (temp);

                if (!m_queue.empty())
                    m_condition.notify_all();
            }

            return *this;
        }

        /*! The move assignment operator */
        SafeQueue& operator= (SafeQueue && sq)
        {
            std::lock_guard<std::mutex> lock (m_mutex);
            m_queue = std::move (sq.m_queue);

            if (!m_queue.empty())  m_condition.notify_all();

            return *this;
        }


    private:

        std::queue<T, Container> m_queue;
        mutable std::mutex m_mutex;
        std::condition_variable m_condition;
        unsigned int m_max_num_items = 0;
};

/*! Swaps the contents of two SafeQueue objects. */
template <class T, class Container>
void swap (SafeQueue<T, Container>& q1, SafeQueue<T, Container>& q2)
{
    q1.swap (q2);
}

#define ThreadSafeQueue SafeQueue

#endif /* SAFEQUEUE_HPP_ */
