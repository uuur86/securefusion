/**
 * @package securefusion
 */

( function($){

	$(document).ready(
		function() {
			if ( typeof new_url !== 'undefined' && new_url ) {
				$( 'form' ).each( function() {
					let action = $( this ).attr( 'action' );
					if ( action && action.indexOf( 'wp-login.php' ) !== -1 ) {
						$( this ).attr( 'action', action.replace( 'wp-login.php', new_url ) );
					}
				});
			}
		}
	);
} )(jQuery);