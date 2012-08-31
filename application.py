from flask import Flask,jsonify
import traceback
import sys
import bcrypt
import logging
import statsd

logger = logging.getLogger('baas')
hdlr = logging.FileHandler('/var/log/baas.log')
formatter =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')

hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)
statsd_connection = statsd.Connection(host='localhost')

app = Flask(__name__)

@app.route('/')
def slash():
	statsd.Counter('baas',statsd_connection).increment('slash',delta=1)
	return jsonify(status="ready"),200
#	return '{"status":"ready"}',200

@app.route('/crypt/<text>')
def crypt(text):
	try:
		hashed = bcrypt.hashpw(text,bcrypt.gensalt())
		statsd.Counter('baas',statsd_connection).increment('crypt')
		return jsonify(hash=hashed),200
#		return '{"hash":"%s"}'%hashed,200		
	except Exception as e:
		err = traceback.format_exception(*sys.exc_info())
		logger.info(err)
#		return u'{"status":"NULL", "reason": "Probably an invalid salt"}' % err,400
		statsd.Counter('baas',statsd_connection).increment('error.crypt',delta=1)
		return jsonify(status="NULL",reason="Probably an invalid salt"),400


@app.route('/ccrypt/<text>/<complexity>')
def ccrypt(text,complexity):
	icomplexity = int(complexity)
	if icomplexity >= 20:
#		return u'{"status":"NULL", "reason": "Huge complexities take an impossible time to calculate. Get real."}',400
		statsd.Counter('baas',statsd_connection).increment('error.ccrypt',delta=1)
		return jsonify(status="NULL", reason="Huge complexities take an impossible time to calculate. Get real."),400
	else:
		try:
			hashed = bcrypt.hashpw(text,bcrypt.gensalt(icomplexity))
			statsd.Counter('baas',statsd_connection).increment('ccrypt',delta=1)
			return jsonify(hash=hashed),200
		except Exception as e:
			err = traceback.format_exception(*sys.exc_info())
			logger.info(err)
			statsd.Counter('baas',statsd_connection).increment('error.ccrypt',delta=1)
			return jsonify(status="NULL",reason="Probably an invalid complexity"),400

@app.route('/scrypt/<text>/<salt>')
def scrypt(text,salt):
	try:
		hashed = bcrypt.hashpw(text,salt)
	except Exception as e:
		err = traceback.format_exception(*sys.exc_info())
		logger.info(err)
		#return u'{"status":"NULL", "reason": "Probably an invalid salt"}' % err,400
		statsd.Counter('baas',statsd_connection).increment('error.scrypt',delta=1)
		return jsonify(status="NULL", reason="Probably an invalid salt"),400

	#return '{"hash":"%s"}'%hashed
	statsd.Counter('baas',statsd_connection).increment('scrypt',delta=1)
	return jsonify(hash=hashed),200

@app.route('/gensalt')
def gensalt():
	try:
		salt = bcrypt.gensalt()
		statsd.Counter('baas',statsd_connection).increment('gensalt',delta=1)
		return jsonify(salt=salt),200
	except Exception as e:
		err = traceback.format_exception(*sys.exc_info())
		logger.info(err)
		statsd.Counter('baas',statsd_connection).increment('error.gensalt',delta=1)
		return jsonify(status="NULL", reason="Failed to generate salt"),500

@app.route('/gensalt/<complexity>')
def cgensalt(complexity):
	try:
		ic = int(complexity)
		salt = bcrypt.gensalt(ic)
		statsd.Counter('baas',statsd_connection).increment('cgensalt',delta=1)
		return jsonify(salt=salt),200
	except Exception as e:
		err = traceback.format_exception(*sys.exc_info())
		logger.info(err)
		statsd.Counter('baas',statsd_connection).increment('error.gensalt',delta=1)
		return jsonify(status="NULL", reason="Failed to generate salt, value %s not valid"%complexity),500



if __name__ == "__main__":
	app.run(debug=True,host="0.0.0.0")

