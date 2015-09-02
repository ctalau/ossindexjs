/**
 *	Copyright (c) 2015 Vör Security Inc.
 *	All rights reserved.
 *	
 *	Redistribution and use in source and binary forms, with or without
 *	modification, are permitted provided that the following conditions are met:
 *	    * Redistributions of source code must retain the above copyright
 *	      notice, this list of conditions and the following disclaimer.
 *	    * Redistributions in binary form must reproduce the above copyright
 *	      notice, this list of conditions and the following disclaimer in the
 *	      documentation and/or other materials provided with the distribution.
 *	    * Neither the name of the <organization> nor the
 *	      names of its contributors may be used to endorse or promote products
 *	      derived from this software without specific prior written permission.
 *	
 *	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *	DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 *	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Provides simplified REST API access
var RestClient = require('node-rest-client').Client;

//RELEASE HOST
var ossindex = "https://ossindex.net";

//DEBUG HOST
//var ossindex = "http://localhost:8080";

//Instantiate the rest client
var client = new RestClient();

module.exports = {
	
	/**
	 * Get artifacts in bulk. Currently this is not supported by the API,
	 * so fake it for now.
	 * 
	 * If an artifact cannot be found it leaves a null in the result array
	 * 
	 * 
	 */
	getNpmArtifacts: function (names, versions, callback, results) {
		var that = this;
		if(results == undefined) {
			results = [];
			// Make sure we don't edit the original arrays
			names = names.slice(0);
			versions = versions.slice(0);
		}
		if(names.length == 0) {
			callback(undefined, results);
			return;
		}
		var name = names.shift();
		var version = versions.shift();
		this.getNpmArtifact(name, version, function(err, artifact) {
			// Push bad results on as well (undefined). This allows
			// the caller to determine which queries return good
			// results.
			results.push(artifact);
			that.getNpmArtifacts(names, versions, callback, results);
		});
	},
	
	/** GET /v1.0/search/artifact/npm/:name/:range
	 * 
	 * Return the artifact that best matches the given package/range
	 */
	getNpmArtifact: function (name, version, callback) {
		var query = ossindex + "/v1.0/search/artifact/npm/" + name + "/" + version;
		client.get(query, function(data, response){
			if(data != undefined && data.length > 0) {
				callback(undefined, data[0]);
			}
			else {
				callback();
			}
		});
	},
	
	/** GET /v1.0/scm/:id
	 * 
	 * Return the SCM details for the SCM with the specified OSS Index ID.
	 */
	getScms: function (scmIds, callback) {
		var list = scmIds.join(",");
		client.get(ossindex + "/v1.0/scm/" + list, function(data, response){
			if(data != undefined) {
				callback(undefined, data);
			}
			else {
				callback();
			}
		});
	},
	
	/** GET /v1.0/uri/:host/:path
	 * 
	 * Return the SCM details for the SCM with the specified OSS Index ID.
	 */
	getScmByUri: function (uri, callback) {
		var index = uri.indexOf("://");
		var uriHostPath = uri.substring(index + 3, uri.length);
		client.get(ossindex + "/v1.0/uri/" + uriHostPath, function(data, response){
			if(data != undefined) {
				callback(undefined, data);
			}
			else {
				callback();
			}
		});
	},
	
	/** Given a list of CPE URIs, return a list of CPE details.
	 * 
	 * @param cpeList
	 * @param callback
	 */
	getCpeListDetails: function (cpeList, callback, results) {
		var that = this;
		if(results == undefined) {
			results = [];
		}
		if(cpeList.length == 0) {
			callback(undefined, results);
		}
		else {
			var cpe = cpeList.shift();
			this.getCpeFromUri(cpe, function(err, cpes) {
				if(err) {
					callback(err);
				}
				if(cpes != undefined) {
					results = results.concat(cpes);
				}
				that.getCpeListDetails(cpeList, callback, results);
			});
		}
	},
	
	/** Given a CPE URI, fetch the CPE details
	 *  
	 *  A CPE URI looks like this: cpe:/part/vendor/product
	 */
	getCpeFromUri: function (cpe, callback) {
		var cpeId = cpe.substring(5);
		var tokens = cpeId.split(":");
		this.getCpe(tokens[0], tokens[1], tokens[2], callback);
	},
	
	/** GET /v1.0/cpe/:part/:vendor/:product
	 * 
	 * Given a part, vendor, and product, return the CPE details.
	 */
	getCpe: function (part, vendor, product, callback) {
		client.get(ossindex + "/v1.0/cpe/" + part + "/" + vendor + "/" + product, function(data, response){
			if(data != undefined) {
				callback(undefined, data);
			}
			else {
				callback();
			}
		});
	},
	
	/** GET /v1.0/cve/:id
	 * 
	 * Given a CVE OSS Index ID, get all of the details which includes but
	 * is not limited to
	 *   o Score
	 *   o Impact information
	 *   o Affected CPEs with versions
	 *   o Reference information
	 */
	getCves: function (cveIdList, callback, results) {
		var that = this;
		if(results == undefined) {
			results = [];
		}
		if(cveIdList.length == 0) {
			callback(undefined, results);
		}
		
		var ids = cveIdList.join(",");
		client.get(ossindex + "/v1.0/cve/" + ids, function(data, response){
			if(data != undefined) {
				callback(undefined, data);
			}
			else {
				callback();
			}
		});
	}
};