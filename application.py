from flask import Flask,jsonify
import traceback
import sys
import bcrypt
import logging

logger = logging.getLogger('baas')
hdlr = logging.FileHandler('/var/log/baas.log')
formatter =  logging.Formatter('%(asctime)s %(levelname)s %(message)s')

hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

app = Flask(__name__)

@app.route('/')
def slash():
	return jsonify(status="ready"),200
#	return '{"status":"ready"}',200

@app.route('/crypt/<text>')
def crypt(text):
	try:
		hashed = bcrypt.hashpw(text,bcrypt.gensalt())
		return jsonify(hash=hashed),200
#		return '{"hash":"%s"}'%hashed,200		
	except Exception as e:
		err = traceback.format_exception(*sys.exc_info())
		logger.info(err)
#		return u'{"status":"NULL", "reason": "Probably an invalid salt"}' % err,400
		return jsonify(status="NULL",reason="Probably an invalid salt"),400


@app.route('/ccrypt/<text>/<complexity>')
def ccrypt(text,complexity):
	icomplexity = int(complexity)
	if icomplexity >= 20:
#		return u'{"status":"NULL", "reason": "Huge complexities take an impossible time to calculate. Get real."}',400
		return jsonify(status="NULL", reason="Huge complexities take an impossible time to calculate. Get real."),400
	else:
		try:
			hashed = bcrypt.hashpw(text,bcrypt.gensalt(icomplexity))
			return jsonify(hash=hashed),200
		except Exception as e:
			err = traceback.format_exception(*sys.exc_info())
			logger.info(err)
			return jsonify(status="NULL",reason="Probably an invalid complexity"),400

@app.route('/scrypt/<text>/<salt>')
def scrypt(text,salt):
	try:
		hashed = bcrypt.hashpw(text,salt)
	except Exception as e:
		err = traceback.format_exception(*sys.exc_info())
		logger.info(err)
		#return u'{"status":"NULL", "reason": "Probably an invalid salt"}' % err,400
		return jsonify(status="NULL", reason="Probably an invalid salt"),400

	#return '{"hash":"%s"}'%hashed
	return jsonify(hash=hashed),200

@app.route('/gensalt')
def gensalt():
	try:
		salt = bcrypt.gensalt()
		return jsonify(salt=salt),200
	except Exception as e:
		err = traceback.format_exception(*sys.exc_info())
		logger.info(err)
		return jsonify(status="NULL", reason="Failed to generate salt"),500

@app.route('/gensalt/<complexity>')
def cgensalt(complexity):
	try:
		ic = int(complexity)
		salt = bcrypt.gensalt(ic)
		return jsonify(salt=salt),200
	except Exception as e:
		err = traceback.format_exception(*sys.exc_info())
		logger.info(err)
		return jsonify(status="NULL", reason="Failed to generate salt, value %s not valid"%complexity),500



if __name__ == "__main__":
	app.run(debug=True,host="0.0.0.0")

