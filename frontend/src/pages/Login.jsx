import React, { useContext, useEffect, useState } from 'react'
import { AppContext } from '../context/AppContext'
import axios from 'axios'
import { toast } from 'react-toastify'
import { useNavigate } from 'react-router-dom'
import { GoogleLogin } from '@react-oauth/google'

const Login = () => {

  const { backendUrl, token, setToken } = useContext(AppContext)
  const navigate = useNavigate()

  // Send the Google ID token (OpenID Connect credential) to our backend, which
  // verifies it with Google and returns our own app session token.
  const handleGoogleSuccess = async (credentialResponse) => {
    try {
      const { data } = await axios.post(backendUrl + '/api/user/auth/google', {
        credential: credentialResponse.credential,
      })
      if (data.success) {
        localStorage.setItem('token', data.token)
        setToken(data.token)
      } else {
        toast.error(data.message)
      }
    } catch (error) {
      toast.error('Google sign-in failed. Please try again.')
    }
  }

  const [state,setState] = useState('Sign Up')

  const [email,setEmail] = useState('')
  const [password,setPassword] = useState('')
  const [name,setName] = useState('')

  // event.preventDefault() -> this will not reload the page again
  const onSubmitHandler = async (event) => {
    event.preventDefault()

    try {
      
      if (state === 'Sign Up') {
        
        const {data} = await axios.post(backendUrl + '/api/user/register',{name,password,email})

        if(data.success){
          localStorage.setItem('token',data.token)
          setToken(data.token)
        }
        else{
          toast.error(data.message)
        }

      } 
      else{

        const {data} = await axios.post(backendUrl + '/api/user/login',{password,email})

        if(data.success){
          localStorage.setItem('token',data.token)
          setToken(data.token)
        }
        else{
          toast.error(data.message)
        }
      }
    } catch (error) {
      toast.error(error.message)
    }
  }

  //once we are logged(that means token gets updated) then we navigate to the home page 
  useEffect(()=>{
    if(token){
      navigate('/')
    }
  },[token])

  return (
    <form onSubmit={onSubmitHandler} className='min-h-[80vh] flex items-center '>
      
      <div className="flex flex-col gap-3 m-auto items-start p-8 min-w-[340px] sm:min-w-96 border rounded-xl text-zinc-600 tx-sm shadow-lg ">
        <p className="text-2xl font-semibold">
          {state === 'Sign Up' ? "Create Account" : "Login"}
        </p>

        <p className="">
          Please {state === 'Sign Up' ? "signup" : "log in"} to book appointment
        </p>

        {
          state === 'Sign Up' && <div className="w-full">
                                    <p className="">Full Name</p>
                                    <input type="text" onChange={(e)=>setName(e.target.value)} value={name} className="w-full p-2 mt-1 border rounded border-zinc-300" />
                                  </div>

        }

        
        <div className="w-full">
          <p className="">Email</p>
          <input type="email" onChange={(e)=>setEmail(e.target.value)} value={email} className="w-full p-2 mt-1 border rounded border-zinc-300" />
        </div>

        <div className="w-full">
          <p className="">Password</p>
          <input type="password" onChange={(e)=>setPassword(e.target.value)} value={password} className="w-full p-2 mt-1 border rounded border-zinc-300" />
        </div>

        <button type='submit' className="w-full py-2 text-base text-white rounded-md bg-primary">
          {state === 'Sign Up' ? "Create Account" : "Log In"}
        </button>

        <div className="flex items-center w-full gap-2 my-1 text-xs text-zinc-400">
          <div className="flex-1 h-px bg-zinc-200"></div>
          <span>OR</span>
          <div className="flex-1 h-px bg-zinc-200"></div>
        </div>

        <div className="flex justify-center w-full">
          <GoogleLogin
            onSuccess={handleGoogleSuccess}
            onError={() => toast.error('Google sign-in failed. Please try again.')}
            useOneTap={false}
          />
        </div>

        {
          state === 'Sign Up'
          ? <p className="">Already have an account? <span onClick={()=>setState('Login')}  className="underline cursor-pointer text-primary">Login here</span></p>
          : <p className="">Create a new Account? <span onClick={()=>setState('Sign Up')}className="underline cursor-pointer text-primary">Click here!</span></p>
        }

      </div>
    </form>
  )
}

export default Login
