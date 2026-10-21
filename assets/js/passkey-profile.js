/* Sentinel Shield: add and remove passkeys on the profile screen. */
( function () {
	'use strict';
	var box = document.getElementById( 'sshield-passkeys' );
	var cfg = window.sshieldPasskey;
	if ( ! box || ! cfg ) {
		return;
	}
	var msg = box.querySelector( '.sshield-pk__msg' );
	var create = box.querySelector( '.sshield-pk__create' );

	function toBytes( text ) {
		var b64 = text.replace( /-/g, '+' ).replace( /_/g, '/' );
		while ( b64.length % 4 ) {
			b64 += '=';
		}
		var bin = atob( b64 );
		var out = new Uint8Array( bin.length );
		for ( var i = 0; i < bin.length; i++ ) {
			out[ i ] = bin.charCodeAt( i );
		}
		return out.buffer;
	}

	function toText( buffer ) {
		var bytes = new Uint8Array( buffer );
		var bin = '';
		for ( var i = 0; i < bytes.length; i++ ) {
			bin += String.fromCharCode( bytes[ i ] );
		}
		return btoa( bin ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	function post( data ) {
		var body = new URLSearchParams();
		data.nonce = cfg.nonce;
		Object.keys( data ).forEach( function ( k ) {
			body.append( k, data[ k ] );
		} );
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
			return r.json();
		} );
	}

	if ( create ) {
		if ( ! window.PublicKeyCredential || ! navigator.credentials ) {
			create.disabled = true;
			msg.textContent = cfg.unsupported;
		}
		create.addEventListener( 'click', function () {
			var name = box.querySelector( '#sshield-pk-name' );
			var pass = box.querySelector( '#sshield-pk-password' );
			if ( pass && ! pass.value ) {
				msg.textContent = cfg.password;
				pass.focus();
				return;
			}
			create.disabled = true;
			msg.textContent = cfg.working;
			post( { action: 'sshield_pk_reg_options', password: pass ? pass.value : '' } )
				.then( function ( res ) {
					if ( ! res.success ) {
						throw new Error( res.data && res.data.message );
					}
					if ( pass ) {
						pass.value = '';
					}
					var pk = res.data;
					pk.challenge = toBytes( pk.challenge );
					pk.user.id = toBytes( pk.user.id );
					pk.excludeCredentials = ( pk.excludeCredentials || [] ).map( function ( c ) {
						return { type: c.type, id: toBytes( c.id ) };
					} );
					return navigator.credentials.create( { publicKey: pk } );
				} )
				.then( function ( cred ) {
					return post( {
						action: 'sshield_pk_register',
						name: name ? name.value : '',
						clientDataJSON: toText( cred.response.clientDataJSON ),
						attestationObject: toText( cred.response.attestationObject )
					} );
				} )
				.then( function ( res ) {
					if ( ! res.success ) {
						throw new Error( res.data && res.data.message );
					}
					msg.textContent = res.data.message;
					window.location.reload();
				} )
				.catch( function ( err ) {
					create.disabled = false;
					if ( err && ( err.name === 'NotAllowedError' || err.name === 'AbortError' ) ) {
						msg.textContent = cfg.cancelled;
					} else if ( err && err.name === 'InvalidStateError' ) {
						msg.textContent = cfg.exists;
					} else {
						msg.textContent = ( err && err.message ) || cfg.failed;
					}
				} );
		} );
	}

	box.addEventListener( 'click', function ( e ) {
		var btn = e.target.closest( '.sshield-pk__remove' );
		if ( ! btn || ! window.confirm( cfg.confirm ) ) {
			return;
		}
		btn.disabled = true;
		post( { action: 'sshield_pk_delete', user: box.getAttribute( 'data-user' ), id: btn.getAttribute( 'data-id' ) } ).then( function ( res ) {
			if ( res.success ) {
				window.location.reload();
			} else {
				btn.disabled = false;
				msg.textContent = ( res.data && res.data.message ) || cfg.failed;
			}
		} );
	} );
} )();
