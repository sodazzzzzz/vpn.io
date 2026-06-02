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

export namespace main {
	
	export class ConnectForm {
	    server: string;
	    serverName: string;
	    mtu: number;
	    tunName: string;
	
	    static createFrom(source: any = {}) {
	        return new ConnectForm(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server = source["server"];
	        this.serverName = source["serverName"];
	        this.mtu = source["mtu"];
	        this.tunName = source["tunName"];
	    }
	}
	export class CredInfo {
	    role: string;
	    fileName: string;
	    loaded: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CredInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.role = source["role"];
	        this.fileName = source["fileName"];
	        this.loaded = source["loaded"];
	    }
	}
	export class CredState {
	    loaded: boolean;
	    fileName: string;
	
	    static createFrom(source: any = {}) {
	        return new CredState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.loaded = source["loaded"];
	        this.fileName = source["fileName"];
	    }
	}
	export class ProfileInfo {
	    hasProfile: boolean;
	    server: string;
	    serverName: string;
	    mtu: number;
	    tunName: string;
	    commonName: string;
	    ca: CredState;
	    cert: CredState;
	    key: CredState;
	
	    static createFrom(source: any = {}) {
	        return new ProfileInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hasProfile = source["hasProfile"];
	        this.server = source["server"];
	        this.serverName = source["serverName"];
	        this.mtu = source["mtu"];
	        this.tunName = source["tunName"];
	        this.commonName = source["commonName"];
	        this.ca = this.convertValues(source["ca"], CredState);
	        this.cert = this.convertValues(source["cert"], CredState);
	        this.key = this.convertValues(source["key"], CredState);
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

}

