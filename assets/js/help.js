/* Sentinel Shield visitor help. Matches questions in the browser; nothing is sent anywhere until the visitor sends a message. */
( function () {
	'use strict';

	var cfg = window.sshieldHelp;
	if ( ! cfg || ! cfg.items ) {
		return;
	}
	var t = cfg.i18n;
	var stop = { a: 1, an: 1, the: 1, i: 1, my: 1, me: 1, is: 1, are: 1, am: 1, to: 1, do: 1, does: 1, did: 1, how: 1, what: 1, why: 1, can: 1, it: 1, of: 1, in: 1, on: 1, for: 1, you: 1, your: 1, and: 1, or: 1, be: 1, this: 1, that: 1, with: 1, was: 1, get: 1, not: 1, no: 1, at: 1, so: 1, if: 1, have: 1, has: 1, please: 1 };

	var words = function ( text ) {
		return String( text || '' ).toLowerCase().replace( /[^\p{L}\p{N}\s]/gu, ' ' ).split( /\s+/ ).filter( function ( w ) {
			return w && ! stop[ w ];
		} );
	};

	// Each item is known by its question words and its keywords; phrases count as their words.
	var index = cfg.items.map( function ( item ) {
		var keys = String( item.k || '' ).split( ',' ).map( function ( k ) {
			return k.trim().toLowerCase();
		} ).filter( Boolean );
		var bag = {};
		words( item.q ).forEach( function ( w ) {
			bag[ w ] = Math.max( bag[ w ] || 0, 1 );
		} );
		keys.forEach( function ( k ) {
			words( k ).forEach( function ( w ) {
				bag[ w ] = 3;
			} );
		} );
		return { item: item, bag: bag, phrases: keys.filter( function ( k ) {
			return k.indexOf( ' ' ) > 0;
		} ) };
	} );

	var match = function ( query ) {
		var q = words( query );
		var lower = String( query ).toLowerCase();
		var scored = index.map( function ( entry ) {
			var score = 0;
			q.forEach( function ( w ) {
				if ( entry.bag[ w ] ) {
					score += entry.bag[ w ];
					return;
				}
				Object.keys( entry.bag ).some( function ( b ) {
					if ( w.length >= 4 && b.length >= 4 && ( 0 === b.indexOf( w ) || 0 === w.indexOf( b ) ) ) {
						score += entry.bag[ b ] - 1;
						return true;
					}
					return false;
				} );
			} );
			entry.phrases.forEach( function ( p ) {
				if ( lower.indexOf( p ) >= 0 ) {
					score += 2;
				}
			} );
			return { item: entry.item, score: score };
		} ).filter( function ( s ) {
			return s.score >= 2;
		} );
		scored.sort( function ( a, b ) {
			return b.score - a.score;
		} );
		return scored;
	};

	var el = function ( tag, cls, text ) {
		var node = document.createElement( tag );
		if ( cls ) {
			node.className = cls;
		}
		if ( text ) {
			node.textContent = text;
		}
		return node;
	};

	// Answers may hold [label](target) links, where target is a known page or an address on the web.
	var rich = function ( node, text ) {
		var re = /\[([^\]]+)\]\(([^)\s]+)\)|(https?:\/\/[^\s)]+)/g;
		var last = 0;
		var m;
		while ( ( m = re.exec( text ) ) ) {
			node.appendChild( document.createTextNode( text.slice( last, m.index ) ) );
			var href = m[ 3 ] || ( cfg.links[ m[ 2 ] ] ? cfg.links[ m[ 2 ] ] : m[ 2 ] );
			if ( /^(https?:\/\/|\/)/i.test( href ) ) {
				var a = el( 'a', '', m[ 1 ] || m[ 3 ] );
				a.href = href;
				a.rel = 'nofollow noopener';
				node.appendChild( a );
			} else {
				node.appendChild( document.createTextNode( m[ 1 ] || m[ 0 ] ) );
			}
			last = re.lastIndex;
		}
		node.appendChild( document.createTextNode( text.slice( last ) ) );
		return node;
	};

	var root;
	var panel;
	var launcher = null;
	if ( cfg.inline ) {
		root = document.getElementById( 'ssh-assistant' );
		if ( ! root ) {
			return;
		}
		panel = root;
		panel.classList.add( 'ssh-chat', 'ssh-chat--inline' );
	} else {
		root = document.querySelector( '.ssh-bubble-root' );
		if ( ! root ) {
			return;
		}
		launcher = el( 'button', 'ssh-launch' );
		launcher.type = 'button';
		launcher.setAttribute( 'aria-expanded', 'false' );
		launcher.setAttribute( 'aria-controls', 'ssh-panel' );
		launcher.setAttribute( 'aria-label', t.open );
		launcher.innerHTML = '<svg viewBox="0 0 24 24" width="24" height="24" aria-hidden="true"><path fill="currentColor" d="M12 3C6.5 3 2 6.9 2 11.7c0 2.4 1.1 4.6 3 6.2L4.3 21l3.9-1.7c1.2.4 2.5.6 3.8.6 5.5 0 10-3.9 10-8.7S17.5 3 12 3Zm-1 13.2h2v2h-2v-2Zm1-10.4c2 0 3.5 1.3 3.5 3 0 1.3-.8 2-1.6 2.6-.6.4-.9.7-.9 1.4v.4h-2v-.6c0-1.3.7-1.9 1.4-2.4.6-.4 1.1-.8 1.1-1.4 0-.7-.7-1.2-1.5-1.2-.9 0-1.5.5-1.7 1.3l-1.9-.5c.4-1.6 1.8-2.6 3.6-2.6Z"/></svg>';
		panel = el( 'div', 'ssh-chat ssh-chat--bubble' );
		panel.id = 'ssh-panel';
		panel.setAttribute( 'role', 'dialog' );
		panel.setAttribute( 'aria-label', cfg.title );
		panel.hidden = true;
		var head = el( 'div', 'ssh-chat__head' );
		head.appendChild( el( 'strong', '', cfg.title ) );
		var close = el( 'button', 'ssh-chat__close', '×' );
		close.type = 'button';
		close.setAttribute( 'aria-label', t.close );
		head.appendChild( close );
		panel.appendChild( head );
		root.appendChild( panel );
		root.appendChild( launcher );
	}

	var log = el( 'div', 'ssh-chat__log' );
	log.setAttribute( 'role', 'log' );
	log.setAttribute( 'aria-live', 'polite' );
	var chips = el( 'div', 'ssh-chat__chips' );
	var form = el( 'form', 'ssh-chat__form' );
	var input = el( 'input', 'ssh-chat__input' );
	input.type = 'text';
	input.maxLength = 200;
	input.placeholder = t.ask;
	input.setAttribute( 'aria-label', t.ask );
	input.autocomplete = 'off';
	var send = el( 'button', 'ssh-chat__send', t.send );
	send.type = 'submit';
	form.appendChild( input );
	form.appendChild( send );
	panel.appendChild( log );
	panel.appendChild( chips );
	panel.appendChild( form );

	var say = function ( who, text, extra ) {
		var row = el( 'div', 'ssh-msg ssh-msg--' + who );
		var label = el( 'span', 'ssh-sr', 'you' === who ? t.you : t.bot );
		row.appendChild( label );
		var bubble = rich( el( 'div', 'ssh-msg__text' ), text );
		row.appendChild( bubble );
		if ( extra ) {
			row.appendChild( extra );
		}
		log.appendChild( row );
		log.scrollTop = log.scrollHeight;
		return row;
	};

	var chipList = function ( items, target ) {
		var box = target || el( 'div', 'ssh-chat__chips ssh-chat__chips--inline' );
		box.textContent = '';
		items.forEach( function ( item ) {
			var b = el( 'button', 'ssh-chip', item.q );
			b.type = 'button';
			b.addEventListener( 'click', function () {
				ask( item.q, item );
			} );
			box.appendChild( b );
		} );
		return box;
	};

	var contactForm = function () {
		if ( ! cfg.contact ) {
			return null;
		}
		var f = el( 'form', 'ssh-contact' );
		var field = function ( name, type, label, required ) {
			var wrap = el( 'label', 'ssh-contact__field' );
			wrap.appendChild( el( 'span', '', label ) );
			var c = el( 'textarea' === type ? 'textarea' : 'input' );
			c.name = name;
			if ( 'textarea' !== type ) {
				c.type = type;
			} else {
				c.rows = 3;
				c.maxLength = 1000;
			}
			c.required = !! required;
			wrap.appendChild( c );
			f.appendChild( wrap );
			return c;
		};
		field( 'name', 'text', t.name, false );
		field( 'email', 'email', t.email, true );
		field( 'message', 'textarea', t.message, true );
		// Left empty by people; bots fill it in.
		var trap = el( 'input' );
		trap.name = 'website';
		trap.tabIndex = -1;
		trap.autocomplete = 'off';
		trap.className = 'ssh-trap';
		trap.setAttribute( 'aria-hidden', 'true' );
		f.appendChild( trap );
		if ( cfg.contact.ref ) {
			f.appendChild( el( 'p', 'ssh-contact__note', t.refIncluded + ' ' + cfg.contact.ref ) );
		}
		var status = el( 'p', 'ssh-contact__status' );
		status.setAttribute( 'role', 'status' );
		var go = el( 'button', 'ssh-chat__send', t.submit );
		go.type = 'submit';
		f.appendChild( go );
		f.appendChild( status );
		f.addEventListener( 'submit', function ( e ) {
			e.preventDefault();
			var body = new window.FormData( f );
			body.append( 'sshield_help', 'ask' );
			body.append( 'token', cfg.contact.token );
			body.append( 'reference', cfg.contact.ref || '' );
			body.append( 'reason', cfg.contact.reason || cfg.context );
			go.disabled = true;
			status.textContent = t.sending;
			window.fetch( window.location.href, { method: 'POST', body: body, credentials: 'same-origin', headers: { Accept: 'application/json' } } )
				.then( function ( r ) {
					return r.json();
				} )
				.then( function ( res ) {
					status.textContent = res.message || t.failed;
					status.className = 'ssh-contact__status ' + ( res.ok ? 'is-ok' : 'is-bad' );
					if ( res.ok ) {
						Array.prototype.forEach.call( f.querySelectorAll( 'input, textarea, button' ), function ( c ) {
							c.disabled = true;
						} );
					} else {
						go.disabled = false;
					}
				} )
				.catch( function () {
					status.textContent = t.failed;
					status.className = 'ssh-contact__status is-bad';
					go.disabled = false;
				} );
		} );
		return f;
	};

	var offerContact = function () {
		if ( ! cfg.contact || log.querySelector( '.ssh-contact, .ssh-chip--strong' ) ) {
			return;
		}
		var b = el( 'button', 'ssh-chip ssh-chip--strong', t.contact );
		b.type = 'button';
		var row = say( 'bot', '', b );
		b.addEventListener( 'click', function () {
			var f = contactForm();
			row.replaceChild( f, b );
			f.querySelector( 'input[name="email"]' ).focus();
		} );
	};

	var ask = function ( text, picked ) {
		say( 'you', text );
		var item = picked;
		var others = [];
		if ( ! item ) {
			var found = match( text );
			item = found.length ? found[ 0 ].item : null;
			others = found.slice( 1, 3 ).map( function ( f ) {
				return f.item;
			} );
		}
		if ( ! item ) {
			say( 'bot', t.none, chipList( cfg.items.slice( 0, 4 ) ) );
			offerContact();
			return;
		}
		if ( 'contact' === item.action ) {
			say( 'bot', item.a );
			var f = contactForm();
			if ( f ) {
				say( 'bot', '', f );
			}
			return;
		}
		say( 'bot', item.a, others.length ? chipList( others ) : null );
		// Someone who was blocked may need a person, whatever they asked.
		if ( 'block' === cfg.context || 'rate' === cfg.context ) {
			offerContact();
		}
	};

	// The first chips: the top questions, and always the way to reach the owner.
	var firstChips = function () {
		var plain = cfg.items.filter( function ( i ) {
			return 'contact' !== i.action;
		} );
		var reach = cfg.items.filter( function ( i ) {
			return 'contact' === i.action;
		} );
		return plain.slice( 0, reach.length ? 4 : 5 ).concat( reach );
	};

	form.addEventListener( 'submit', function ( e ) {
		e.preventDefault();
		var text = input.value.trim();
		if ( ! text ) {
			return;
		}
		input.value = '';
		ask( text );
	} );

	var started = false;
	var start = function () {
		if ( started ) {
			return;
		}
		started = true;
		say( 'bot', cfg.hello );
		chipList( firstChips(), chips );
	};

	if ( cfg.inline ) {
		start();
		return;
	}

	var setOpen = function ( open ) {
		panel.hidden = ! open;
		launcher.setAttribute( 'aria-expanded', open ? 'true' : 'false' );
		launcher.setAttribute( 'aria-label', open ? t.close : t.open );
		root.classList.toggle( 'is-open', open );
		if ( open ) {
			start();
			input.focus();
		} else {
			launcher.focus();
		}
	};
	launcher.addEventListener( 'click', function () {
		setOpen( panel.hidden );
	} );
	panel.querySelector( '.ssh-chat__close' ).addEventListener( 'click', function () {
		setOpen( false );
	} );
	panel.addEventListener( 'keydown', function ( e ) {
		if ( 'Escape' === e.key ) {
			setOpen( false );
		}
	} );
} )();
