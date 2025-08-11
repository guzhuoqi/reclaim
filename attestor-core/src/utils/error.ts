import { ErrorCode, ErrorData } from 'src/proto/api'

/**
 * Represents an error that can be thrown by the Attestor Core
 * or server. Provides a code, and optional data
 * to pass along with the error.
 */
export class AttestorError extends Error {

	readonly name = 'AttestorError'

	constructor(
		public code: keyof typeof ErrorCode,
		public message: string,
		public data?: { [_: string]: any }
	) {
		super(message)
	}

	/**
	 * Encodes the error as a ErrorData
	 * protobuf message
	 */
	toProto() {
		return ErrorData.create({
			code: ErrorCode[this.code],
			message: this.message,
			data: JSON.stringify(this.data)
		})
	}

	static fromProto(data = ErrorData.fromJSON({})) {
		return new AttestorError(
			ErrorCode[data.code] as keyof typeof ErrorCode,
			data.message,
			data.data ? JSON.parse(data.data) : undefined
		)
	}

  static fromError(err: Error) {
    if(err instanceof AttestorError) {
      return err
    }

    // Ensure we never emit an empty error message
    const fallbackMessage = 'Unknown error'
    const rawMessage = (err && typeof err.message === 'string')
      ? err.message
      : ''
    const message = rawMessage && rawMessage.trim().length > 0
      ? rawMessage
      : fallbackMessage

    // Attach basic diagnostic metadata when available
    const anyErr = err as unknown as { [k: string]: any }
    const data: { [k: string]: any } = {}
    if(anyErr) {
      if(typeof anyErr.name === 'string') data.causeName = anyErr.name
      if(typeof anyErr.code !== 'undefined') data.code = anyErr.code
      if(typeof anyErr.errno !== 'undefined') data.errno = anyErr.errno
      if(typeof anyErr.syscall === 'string') data.syscall = anyErr.syscall
      if(typeof anyErr.address === 'string') data.address = anyErr.address
      if(typeof anyErr.port !== 'undefined') data.port = anyErr.port
    }

    return new AttestorError(
      'ERROR_INTERNAL',
      message,
      Object.keys(data).length ? data : undefined,
    )
  }

	static badRequest(message: string, data?: { [_: string]: any }) {
		return new AttestorError(
			'ERROR_BAD_REQUEST',
			message,
			data
		)
	}
}