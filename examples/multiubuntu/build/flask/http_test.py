#!/usr/bin/python -O

import sys
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
	return "URL: /\n"

@app.route('/test1')
def test1():
	return "URL: /test1\n"

@app.route('/test2')
def test2():
	return "URL: /test2\n"

if len(sys.argv) != 2:
	print("Usage: {} [port]".format(sys.argv[0]))

app.run(host='0.0.0.0', port=int(sys.argv[1]), threaded=True)
