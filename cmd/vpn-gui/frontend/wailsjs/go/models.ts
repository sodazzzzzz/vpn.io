export namespace control {
	
	export class Connected {
	    commonName: string;
	    // Go type: time
	    notAfter: any;
	
	    static createFrom(source: any = {}) {
	        return new Connected(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.commonName = source["commonName"];
	        this.notAfter = this.convertValues(source["notAfter"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Credentials {
	    server: string;
	    serverName?: string;
	    caCertPem: number[];
	    certPem: number[];
	    keyPem: number[];
	    mtu?: number;
	    tunName?: string;
	
	    static createFrom(source: any = {}) {
	        return new Credentials(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server = source["server"];
	        this.serverName = source["serverName"];
	        this.caCertPem = source["caCertPem"];
	        this.certPem = source["certPem"];
	        this.keyPem = source["keyPem"];
	        this.mtu = source["mtu"];
	        this.tunName = source["tunName"];
	    }
	}
	export class Status {
	    state: string;
	    server: string;
	    sinceUnix: number;
	    lastError: string;
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.server = source["server"];
	        this.sinceUnix = source["sinceUnix"];
	        this.lastError = source["lastError"];
	    }
	}

}

