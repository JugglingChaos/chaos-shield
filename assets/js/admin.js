/* Sentinel Shield admin enhancements. The page works without this file. */
( function () {
	'use strict';

	// Animate the score ring from zero.
	var bar = document.querySelector( '.sshield-score__bar' );
	if ( bar ) {
		var target = bar.style.strokeDasharray;
		bar.style.strokeDasharray = '0 100';
		window.requestAnimationFrame( function () {
			window.requestAnimationFrame( function () {
				bar.style.strokeDasharray = target;
			} );
		} );
	}

	// Highlight module cards that are switched on.
	document.querySelectorAll( '.sshield-module' ).forEach( function ( card ) {
		var input = card.querySelector( 'input[type="checkbox"]' );
		if ( ! input ) {
			return;
		}
		var sync = function () {
			card.classList.toggle( 'is-on', input.checked );
		};
		input.addEventListener( 'change', sync );
		sync();
	} );

	// Scan tab: start a scan and drive it in small steps until it finishes.
	var box = document.querySelector( '.sshield-scanbox' );
	if ( box && window.sshieldAdmin ) {
		var cfg = window.sshieldAdmin;
		var button = box.querySelector( '.sshield-scan-start' );
		var panel = box.querySelector( '.sshield-progress' );
		var fill = box.querySelector( '.sshield-progress__bar span' );
		var text = box.querySelector( '.sshield-progress__text' );

		var call = function ( op ) {
			var body = new window.FormData();
			body.append( 'action', 'sshield_scan' );
			body.append( 'op', op );
			body.append( '_ajax_nonce', cfg.nonce );
			return window.fetch( cfg.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' } )
				.then( function ( response ) {
					return response.json();
				} );
		};

		var show = function ( p ) {
			fill.style.width = p.percent + '%';
			text.textContent = p.total
				? cfg.i18n.progress.replace( '%1$s', p.done.toLocaleString() ).replace( '%2$s', p.total.toLocaleString() )
				: cfg.i18n.preparing;
		};

		var loop = function ( op ) {
			call( op ).then( function ( res ) {
				if ( ! res || ! res.success ) {
					throw new Error( 'scan' );
				}
				show( res.data );
				if ( 'running' === res.data.status ) {
					loop( 'step' );
				} else {
					window.location.reload();
				}
			} ).catch( function () {
				text.textContent = cfg.i18n.failed;
				button.disabled = false;
			} );
		};

		button.addEventListener( 'click', function () {
			button.disabled = true;
			panel.hidden = false;
			show( { percent: 0, total: 0, done: 0 } );
			loop( 'start' );
		} );

		// Resume a scan that was already running when the page loaded.
		if ( '1' === box.getAttribute( 'data-running' ) ) {
			loop( 'step' );
		}
	}
	// Live traffic: fetch new rows every few seconds while the tab is visible.
	var traffic = document.querySelector( '.sshield-traffic' );
	if ( traffic && window.sshieldAdmin && traffic.querySelector( 'tbody' ) ) {
		var tcfg = window.sshieldAdmin;
		var tbody = traffic.querySelector( 'tbody' );
		var empty = traffic.querySelector( '.sshield-empty' );
		var toggle = traffic.querySelector( '.sshield-live__toggle' );
		var last = parseInt( traffic.getAttribute( 'data-last' ), 10 ) || 0;
		var busy = false;

		var poll = function () {
			if ( busy || document.hidden || ( toggle && ! toggle.checked ) ) {
				return;
			}
			busy = true;
			var body = new window.FormData();
			body.append( 'action', 'sshield_traffic' );
			body.append( 'kind', traffic.getAttribute( 'data-kind' ) );
			body.append( 'country', traffic.getAttribute( 'data-country' ) || '' );
			body.append( 'after', String( last ) );
			body.append( '_ajax_nonce', tcfg.traffic );
			window.fetch( tcfg.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' } )
				.then( function ( response ) {
					return response.json();
				} )
				.then( function ( res ) {
					if ( ! res || ! res.success ) {
						return;
					}
					if ( res.data.html ) {
						var tmp = document.createElement( 'tbody' );
						tmp.innerHTML = res.data.html;
						var rows = Array.prototype.slice.call( tmp.children );
						rows.reverse().forEach( function ( row ) {
							row.classList.add( 'is-new' );
							tbody.insertBefore( row, tbody.firstChild );
						} );
						// Keep the page light on long sessions.
						while ( tbody.children.length > 300 ) {
							tbody.removeChild( tbody.lastChild );
						}
						if ( empty ) {
							empty.hidden = true;
						}
					}
					last = res.data.last;
					var total = 0;
					Object.keys( res.data.counts ).forEach( function ( k ) {
						total += res.data.counts[ k ];
						var el = traffic.querySelector( '[data-count="' + k + '"]' );
						if ( el ) {
							el.textContent = res.data.counts[ k ].toLocaleString();
						}
					} );
					var all = traffic.querySelector( '[data-count="all"]' );
					if ( all ) {
						all.textContent = total.toLocaleString();
					}
				} )
				.catch( function () {} )
				.then( function () {
					busy = false;
				} );
		};
		window.setInterval( poll, 5000 );
	}

	// Traffic map: switch the measure, show a tooltip, click a country to filter the table.
	var geo = document.querySelector( '.sshield-geo' );
	if ( geo ) {
		var gdata = JSON.parse( geo.getAttribute( 'data-geo' ) || '{}' );
		var counts = gdata.counts || {};
		var shapes = geo.querySelectorAll( '.sshield-geo__c' );
		var tip = geo.querySelector( '.sshield-geo__tip' );
		var mapBox = geo.querySelector( '.sshield-geo__map' );
		var maxLabel = geo.querySelector( '.sshield-geo__max' );
		var maxTemplate = maxLabel ? maxLabel.textContent.replace( /[\d.,\s\u00a0\u202f]+\)$/, ' %s)' ) : '';
		var fmt = function ( n ) {
			return ( n || 0 ).toLocaleString();
		};
		var paint = function ( metric ) {
			var max = 0;
			Object.keys( counts ).forEach( function ( cc ) {
				max = Math.max( max, counts[ cc ][ metric ] || 0 );
			} );
			Array.prototype.forEach.call( shapes, function ( el ) {
				var c = counts[ el.getAttribute( 'data-cc' ) ];
				var n = c ? c[ metric ] || 0 : 0;
				var step = n > 0 && max > 0 ? Math.max( 1, Math.min( 5, Math.ceil( 5 * Math.log( 1 + n ) / Math.log( 1 + max ) ) ) ) : 0;
				el.setAttribute( 'class', el.getAttribute( 'class' ).replace( /sshield-geo--\d/, 'sshield-geo--' + step ) );
			} );
			if ( maxLabel && maxTemplate ) {
				maxLabel.textContent = maxTemplate.replace( '%s', fmt( max ) );
			}
		};
		Array.prototype.forEach.call( geo.querySelectorAll( '[data-metric]' ), function ( btn ) {
			btn.addEventListener( 'click', function () {
				Array.prototype.forEach.call( geo.querySelectorAll( '[data-metric]' ), function ( b ) {
					b.classList.toggle( 'is-active', b === btn );
					b.setAttribute( 'aria-pressed', b === btn ? 'true' : 'false' );
				} );
				paint( btn.getAttribute( 'data-metric' ) );
			} );
		} );
		var show = function ( el, evt ) {
			var cc = el.getAttribute( 'data-cc' );
			var c = counts[ cc ];
			var name = ( gdata.names && gdata.names[ cc ] ) || el.getAttribute( 'data-name' ) || cc;
			var line = c ? gdata.i18n.tip.replace( '%1$s', fmt( c.all ) ).replace( '%2$s', fmt( c.blocked ) ).replace( '%3$s', fmt( c.login ) ).replace( '%4$s', fmt( c.ips ) ) : gdata.i18n.none;
			tip.textContent = '';
			var strong = document.createElement( 'strong' );
			strong.textContent = name;
			tip.appendChild( strong );
			tip.appendChild( document.createTextNode( ' ' + line ) );
			tip.hidden = false;
			var box = mapBox.getBoundingClientRect();
			var x = evt.clientX - box.left;
			var y = evt.clientY - box.top;
			tip.style.left = Math.max( 8, Math.min( box.width - tip.offsetWidth - 8, x - tip.offsetWidth / 2 ) ) + 'px';
			tip.style.top = Math.max( 8, y - tip.offsetHeight - 14 ) + 'px';
			el.classList.add( 'is-hover' );
		};
		Array.prototype.forEach.call( shapes, function ( el ) {
			el.addEventListener( 'mousemove', function ( evt ) {
				show( el, evt );
			} );
			el.addEventListener( 'mouseleave', function () {
				tip.hidden = true;
				el.classList.remove( 'is-hover' );
			} );
			if ( counts[ el.getAttribute( 'data-cc' ) ] ) {
				el.classList.add( 'has-data' );
				el.addEventListener( 'click', function () {
					var url = new window.URL( window.location.href );
					url.searchParams.set( 'country', el.getAttribute( 'data-cc' ) );
					url.hash = 'sshield-traffic';
					window.location.href = url.toString();
				} );
			}
		} );
	}

	// Connections: open a service's sign-up page in a small window beside this one, then check and save what comes back.
	var ccfg = window.sshieldAdmin;
	var connectCall = function ( data ) {
		var body = new window.FormData();
		body.append( 'action', 'sshield_connect' );
		body.append( '_ajax_nonce', ccfg.connect );
		Object.keys( data ).forEach( function ( k ) {
			body.append( k, data[ k ] );
		} );
		return window.fetch( ccfg.ajaxUrl, { method: 'POST', body: body, credentials: 'same-origin' } )
			.then( function ( response ) {
				return response.json();
			} );
	};
	var say = function ( el, text, tone ) {
		if ( ! el ) {
			return;
		}
		el.hidden = ! text;
		el.textContent = text || '';
		el.classList.toggle( 'is-ok', 'ok' === tone );
		el.classList.toggle( 'is-bad', 'bad' === tone );
	};

	var openPopup = function ( url ) {
		var w = Math.min( 640, window.screen.availWidth - 40 );
		var h = Math.min( 780, window.screen.availHeight - 60 );
		var left = Math.max( 0, window.screenX + window.outerWidth - w - 24 );
		var top = Math.max( 0, window.screenY + 70 );
		// Open blank first and cut the link back to this page, then load the service.
		var win = window.open( 'about:blank', 'sshield_connect', 'popup=yes,width=' + w + ',height=' + h + ',left=' + left + ',top=' + top );
		if ( ! win ) {
			return null;
		}
		try {
			win.opener = null;
		} catch ( e ) {}
		win.location.href = url;
		win.focus();
		return win;
	};

	var scripts = {};
	var loadScript = function ( src ) {
		if ( ! scripts[ src ] ) {
			scripts[ src ] = new Promise( function ( resolve, reject ) {
				var tag = document.createElement( 'script' );
				tag.src = src;
				tag.async = true;
				tag.onload = resolve;
				tag.onerror = reject;
				document.head.appendChild( tag );
			} );
		}
		return scripts[ src ];
	};

	document.querySelectorAll( 'dialog.sshield-connect' ).forEach( function ( dialog ) {
		var service = dialog.getAttribute( 'data-service' );
		var msg = dialog.querySelector( '.sshield-connect__msg' );
		var save = dialog.querySelector( '[data-save]' );
		var force = dialog.querySelector( '[data-force]' );
		var blocked = dialog.querySelector( '.sshield-connect__blocked' );
		var inputs = dialog.querySelectorAll( 'input' );
		var preview = dialog.querySelector( '.sshield-connect__preview' );
		var keyInput = dialog.querySelector( 'input[name="site_key"]' );
		var keyTest = dialog.getAttribute( 'data-key-test' ) ? new RegExp( dialog.getAttribute( 'data-key-test' ), 'i' ) : null;
		var token = '';
		var widget = null;
		var shownKey = '';
		var watch = null;

		var api = function () {
			return 'hcaptcha' === service ? window.hcaptcha : window.turnstile;
		};
		var renderPreview = function () {
			if ( ! preview || ! keyInput ) {
				return;
			}
			var key = keyInput.value.trim();
			if ( key === shownKey ) {
				return;
			}
			shownKey = key;
			token = '';
			if ( null !== widget && api() ) {
				try {
					api().remove( widget );
				} catch ( e ) {}
				widget = null;
			}
			var mount = preview.querySelector( '.sshield-connect__widget' );
			mount.textContent = '';
			if ( ! keyTest || ! keyTest.test( key ) ) {
				preview.hidden = true;
				return;
			}
			preview.hidden = false;
			loadScript( dialog.getAttribute( 'data-script' ) ).then( function () {
				var tries = 0;
				var ready = function () {
					if ( ! api() || ! api().render ) {
						if ( tries++ < 40 ) {
							window.setTimeout( ready, 100 );
						}
						return;
					}
					if ( key !== shownKey ) {
						return;
					}
					var box = document.createElement( 'div' );
					mount.appendChild( box );
					widget = api().render( box, {
						sitekey: key,
						theme: 'dark',
						callback: function ( t ) {
							token = t;
							say( msg, ccfg.i18n.passed, 'ok' );
						},
						'expired-callback': function () {
							token = '';
						},
						'error-callback': function ( code ) {
							token = '';
							code = String( code || '' );
							say( msg, 0 === code.indexOf( '1102' ) ? ccfg.i18n.domain : ( 0 === code.indexOf( '1101' ) ? ccfg.i18n.badKey : '' ), 'bad' );
							return true;
						},
					} );
				};
				ready();
			} ).catch( function () {
				preview.hidden = true;
			} );
		};
		if ( keyInput ) {
			keyInput.addEventListener( 'input', renderPreview );
			keyInput.addEventListener( 'change', renderPreview );
		}

		dialog.querySelector( '[data-popup]' ).addEventListener( 'click', function () {
			var win = openPopup( dialog.getAttribute( 'data-open' ) );
			blocked.hidden = !! win;
			if ( ! win ) {
				return;
			}
			window.clearInterval( watch );
			watch = window.setInterval( function () {
				if ( win.closed ) {
					window.clearInterval( watch );
					say( msg, ccfg.i18n.back, '' );
					var empty = Array.prototype.filter.call( inputs, function ( i ) {
						return ! i.value && ! i.hasAttribute( 'data-saved' );
					} );
					( empty[ 0 ] || inputs[ 0 ] ).focus();
				}
			}, 600 );
		} );

		var submit = function ( forced ) {
			var data = { service: service, op: 'save', token: token, force: forced ? '1' : '' };
			inputs.forEach( function ( i ) {
				data[ i.name ] = i.value.trim();
			} );
			save.disabled = true;
			force.hidden = true;
			say( msg, ccfg.i18n.checking, '' );
			connectCall( data ).then( function ( res ) {
				if ( res && res.success ) {
					say( msg, res.data.message, 'ok' );
					window.setTimeout( function () {
						window.location.reload();
					}, 1400 );
					return;
				}
				say( msg, res && res.data && res.data.message ? res.data.message : ccfg.i18n.failedCall, 'bad' );
				force.hidden = ! ( res && res.data && res.data.unreachable );
				save.disabled = false;
			} ).catch( function () {
				say( msg, ccfg.i18n.failedCall, 'bad' );
				save.disabled = false;
			} );
		};
		save.addEventListener( 'click', function () {
			submit( false );
		} );
		force.addEventListener( 'click', function () {
			submit( true );
		} );
		dialog.querySelector( '.sshield-connect__form' ).addEventListener( 'submit', function ( e ) {
			e.preventDefault();
			submit( false );
		} );
		dialog.querySelectorAll( '[data-close]' ).forEach( function ( b ) {
			b.addEventListener( 'click', function () {
				dialog.close();
			} );
		} );
		// A click on the backdrop closes the dialog.
		dialog.addEventListener( 'click', function ( e ) {
			if ( e.target === dialog ) {
				dialog.close();
			}
		} );
		dialog.addEventListener( 'close', function () {
			window.clearInterval( watch );
		} );
		dialog.sshieldOpen = function () {
			say( msg, '', '' );
			force.hidden = true;
			blocked.hidden = true;
			save.disabled = false;
			dialog.showModal();
			renderPreview();
			var first = Array.prototype.filter.call( inputs, function ( i ) {
				return ! i.value && ! i.hasAttribute( 'data-saved' );
			} )[ 0 ];
			dialog.querySelector( '[data-popup]' ).focus();
			if ( first && first !== inputs[ 0 ] ) {
				first.focus();
			}
		};
	} );

	document.addEventListener( 'click', function ( e ) {
		var btn = e.target.closest ? e.target.closest( '[data-connect], [data-connect-remove], [data-connect-test]' ) : null;
		if ( ! btn || ! ccfg ) {
			return;
		}
		e.preventDefault();
		var card = btn.closest( '.sshield-card' );
		var status = card ? card.querySelector( '.sshield-connection__status' ) : null;
		if ( btn.hasAttribute( 'data-connect' ) ) {
			var dialog = document.getElementById( 'sshield-connect-' + btn.getAttribute( 'data-connect' ) );
			if ( dialog && dialog.sshieldOpen ) {
				dialog.sshieldOpen();
			}
			return;
		}
		var removing = btn.hasAttribute( 'data-connect-remove' );
		if ( removing && ! window.confirm( ccfg.i18n.remove ) ) {
			return;
		}
		btn.disabled = true;
		say( status, ccfg.i18n.sending, '' );
		connectCall( {
			service: btn.getAttribute( removing ? 'data-connect-remove' : 'data-connect-test' ),
			op: removing ? 'disconnect' : 'test',
		} ).then( function ( res ) {
			say( status, res && res.data && res.data.message ? res.data.message : ccfg.i18n.failedCall, res && res.success ? 'ok' : 'bad' );
			btn.disabled = false;
			if ( removing && res && res.success ) {
				window.setTimeout( function () {
					window.location.reload();
				}, 900 );
			}
		} ).catch( function () {
			say( status, ccfg.i18n.failedCall, 'bad' );
			btn.disabled = false;
		} );
	} );

	// Visitor help: add and remove FAQ rows, keeping the field names in order.
	var faq = document.querySelector( '.sshield-faq' );
	if ( faq ) {
		var renumber = function () {
			Array.prototype.forEach.call( faq.querySelectorAll( '.sshield-faq__row' ), function ( row, i ) {
				row.querySelectorAll( '[name^="faq["]' ).forEach( function ( f ) {
					f.name = f.name.replace( /^faq\[\d+\]/, 'faq[' + i + ']' );
				} );
			} );
		};
		faq.addEventListener( 'click', function ( e ) {
			if ( ! e.target.classList.contains( 'sshield-faq__remove' ) ) {
				return;
			}
			var row = e.target.closest( '.sshield-faq__row' );
			if ( faq.querySelectorAll( '.sshield-faq__row' ).length > 1 ) {
				row.parentNode.removeChild( row );
			} else {
				row.querySelectorAll( 'input, textarea' ).forEach( function ( f ) {
					f.value = '';
				} );
			}
			renumber();
		} );
		document.querySelector( '.sshield-faq__add' ).addEventListener( 'click', function () {
			var rows = faq.querySelectorAll( '.sshield-faq__row' );
			if ( rows.length >= parseInt( faq.getAttribute( 'data-max' ), 10 ) ) {
				return;
			}
			var copy = rows[ rows.length - 1 ].cloneNode( true );
			copy.querySelectorAll( 'input, textarea' ).forEach( function ( f ) {
				f.value = '';
			} );
			faq.appendChild( copy );
			renumber();
			copy.querySelector( 'input' ).focus();
		} );
	}

	// Copy buttons next to read-only addresses.
	document.addEventListener( 'click', function ( e ) {
		var btn = e.target.closest ? e.target.closest( '[data-copy]' ) : null;
		var input = btn ? btn.parentNode.querySelector( 'input' ) : null;
		if ( ! input ) {
			return;
		}
		input.select();
		var done = function () {
			var label = btn.textContent;
			btn.textContent = '✓';
			window.setTimeout( function () {
				btn.textContent = label;
			}, 1200 );
		};
		if ( window.navigator.clipboard ) {
			window.navigator.clipboard.writeText( input.value ).then( done, function () {} );
		} else {
			document.execCommand( 'copy' );
			done();
		}
	} );

	// Forms that undo or delete something ask first.
	document.addEventListener( 'submit', function ( e ) {
		var form = e.target;
		if ( form && form.getAttribute && form.getAttribute( 'data-confirm' ) && ! window.confirm( form.getAttribute( 'data-confirm' ) ) ) {
			e.preventDefault();
		}
	} );
} )();
