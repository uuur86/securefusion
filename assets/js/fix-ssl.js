/**
 * @package securefusion
 */

( function($){

	$(document).ready( function() {

		$.each($.find('img[src^="http://"],link[href^="http://"]'), function (key, value) {
			if( value.tagName == 'LINK' ) {
				$( 'link[href="' + value.href + '"]' ).attr( 'href', 'https://' + value.href.substring( 7 ) );
			}
			else {
				$( 'img[src="' + value.src + '"]' ).attr( 'src', 'https://' + value.src.substring( 7 ) );
			}

		});
	} );

} )(jQuery);