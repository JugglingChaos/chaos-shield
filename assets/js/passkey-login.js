/* Sentinel Shield: "Sign in with a passkey" on the login page. */
( function () {
	'use strict';
	var box = document.querySelector( '.sshield-pk-login' );
	var cfg = window.sshieldPasskey;
	if ( ! box || ! cfg || ! window.PublicKeyCredential || ! navigator.credentials ) {
		return;
	}
	var btn = box.querySelector( '.sshield-pk-login__btn' );
	var msg = box.querySelector( '.sshield-pk-login__msg' );
	var submit = document.querySelector( '#loginform .submit' );
	if ( submit ) {
		submit.parentNode.insertBefore( box, submit.nextSibling );
	}
	box.hidden = false;

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
		Object.keys( data ).forEach( function ( k ) {
			body.append( k, data[ k ] );
		} );
		return fetch( cfg.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
			return r.json();
		} );
	}

	function fail( text ) {
		msg.textContent = text || cfg.failed;
		btn.disabled = false;
	}

	btn.addEventListener( 'click', function () {
		btn.disabled = true;
		msg.textContent = cfg.working;
		var ticket;
		post( { action: 'sshield_pk_login_options' } )
			.then( function ( res ) {
				if ( ! res.success ) {
					throw new Error( res.data && res.data.message );
				}
				ticket = res.data.ticket;
				var pk = res.data.publicKey;
				pk.challenge = toBytes( pk.challenge );
				return navigator.credentials.get( { publicKey: pk } );
			} )
			.then( function ( cred ) {
				var redirect = document.querySelector( 'input[name="redirect_to"]' );
				return post( {
					action: 'sshield_pk_login',
					ticket: ticket,
					id: toText( cred.rawId ),
					clientDataJSON: toText( cred.response.clientDataJSON ),
					authenticatorData: toText( cred.response.authenticatorData ),
					signature: toText( cred.response.signature ),
					redirect_to: redirect ? redirect.value : ''
				} );
			} )
			.then( function ( res ) {
				if ( ! res.success ) {
					throw new Error( res.data && res.data.message );
				}
				window.location.href = res.data.redirect;
			} )
			.catch( function ( err ) {
				fail( err && err.name !== 'NotAllowedError' && err.message ? err.message : '' );
			} );
	} );
} )();
