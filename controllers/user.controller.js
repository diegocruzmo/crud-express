import bcryptjs from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { UserModel } from '../models/user.model.js'

const register = async (req, res) => {
  try {
    console.log(req.body)
    const { username, email, password } = req.body

    if (!username || !email || !password) {
      return res
        .status(400)
        .json({ ok: false, msg: 'Missing required fields!' })
    }

    const user = await UserModel.findOneByEmail(email)

    if (user) {
      return res.status(409).json({ ok: false, msg: 'User already exists!' })
    }

    const salt = await bcryptjs.genSalt(10)
    const hashedPassword = await bcryptjs.hash(password, salt)

    const newUser = await UserModel.create({
      username,
      email,
      password: hashedPassword
    })

    const token = jwt.sign(
      {
        email: newUser.email
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    )

    return res.json({ ok: true, token: token })
  } catch (error) {
    console.log(error)
    return res.status(500).json({
      ok: false,
      msg: 'Server error'
    })
  }
}

const login = async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res
        .status(400)
        .json({ ok: false, msg: 'Missing required fields!' })
    }

    const user = await UserModel.findOneByEmail(email)

    if (!user) {
      return res.status(409).json({ ok: false, msg: 'User not found!' })
    }

    const isMatch = await bcryptjs.compare(password, user.password)

    if (!isMatch) {
      return res.status(401).json({ ok: false, msg: 'Password incorrect!' })
    }

    const token = jwt.sign(
      {
        email: user.email
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    )

    return res.json({ ok: true, token: token })
  } catch (error) {
    console.log(error)
    return res.status(500).json({
      ok: false,
      msg: 'Server error'
    })
  }
}

const profile = async (req, res) => {
  try {
    const user = await UserModel.findOneByEmail(email)
    return res.json({ ok: true, msg: user })
  } catch (error) {
    console.log(error)
    return res.status(500).json({
      ok: false,
      msg: 'Server error'
    })
  }
}

export const UserController = { register, login, profile }
