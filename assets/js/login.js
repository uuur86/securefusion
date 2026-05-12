/**
 * @package securefusion
 */

( function($){

	$(document).ready(
		function() {
            $( '#wp-submit' ).on( 'click',
                function( event ) {
                event.preventDefault();
                let parent  = $( '#wp-submit' ).parents( 'form' );

                parent.attr( 'action',
                    parent.attr( 'action' ).replace( 'wp-login.php' , new_url ) ).submit();
                }
            );
        }
	);
} )(jQuery);