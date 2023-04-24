import * as Joi from 'joi'
import * as dotenv from 'dotenv'

dotenv.config()

const envVarsSchema = Joi.object()
  .keys({
    TOTAL_MEMBER: Joi.number().default(5),
    THRESHOLD: Joi.number().default(2),
    DEALERS: Joi.number().default(3),
  })
  .unknown()

const { value: envVars, error } = envVarsSchema
  .prefs({ errors: { label: 'key' } })
  .validate(process.env)

if (error) {
  throw new Error(`Config validation error: ${error.message}`)
}

export default {
  totalMember: envVars.TOTAL_MEMBER,
  threshold: envVars.THRESHOLD,
  dealers: envVars.DEALERS,
}
