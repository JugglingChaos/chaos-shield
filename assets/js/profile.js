/* Chaos Shield: draws the two-factor setup QR code on the profile screen. */
( function () {
	'use strict';
	var box = document.querySelector( '.cshield-2fa__qr' );
	if ( ! box || typeof window.qrcode !== 'function' ) {
		return;
	}
	var qr = window.qrcode( 0, 'M' );
	qr.addData( box.getAttribute( 'data-uri' ) );
	qr.make();
	box.innerHTML = qr.createSvgTag( { cellSize: 4, margin: 2, scalable: true } );
} )();
