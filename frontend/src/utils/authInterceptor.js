import axios from 'axios'

// Auth header name -> callback that clears that session.
const sessionHandlers = new Map()

// Did this request carry the given auth header?
const sentHeader = (config, name) => {
  const headers = config?.headers
  if (!headers) return false
  return Boolean(typeof headers.get === 'function' ? headers.get(name) : headers[name])
}

// Installed once, when this module is first imported, so it already covers
// the very first API requests. (Pages fire requests in their own effects,
// which run before the context providers' effects.)
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    // Show the API's own safe message instead of axios' generic
    // "Request failed with status code 4xx".
    const apiMessage = error.response?.data?.message
    if (typeof apiMessage === 'string') error.message = apiMessage

    // 401 = token expired, revoked or invalid: clear that session.
    if (error.response?.status === 401) {
      for (const [headerName, clearSession] of sessionHandlers) {
        if (sentHeader(error.config, headerName)) clearSession()
      }
    }
    return Promise.reject(error)
  }
)

/**
 * Register the callback that clears the session whose token is sent in
 * `headerName`. Safe to call on every render (it replaces the previous one).
 */
export const onSessionRejected = (headerName, clearSession) => {
  sessionHandlers.set(headerName, clearSession)
}
