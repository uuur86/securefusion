/**
 * @package securefusion
 */

( function($){

	$(document).ready( function() {
		let loc_href = $( location ).attr( 'href' ).split( '#' );

		function securefusion_reset_tab_nav() {
			$( '.content-tab-wrapper > .tab-content' ).addClass( 'hidden' );
			$( '.nav-tab-wrapper > a' ).removeClass( 'nav-tab-active' );
		}

		function securefusion_tab_activate( selected_id = null ) {

			if( selected_id === null ) {

				if( loc_href.length > 1 ) {
					selected_id = loc_href[ 1 ];
				}

				if( selected_id === null ) {
					selected_obj = $( '.nav-tab-wrapper > a' ).first();

					if( selected_obj.is( 'a' ) ) {
						selected_id = selected_obj.attr( 'href' ).split( '#' )[ 1 ];
					}
				}
			}

			var content_id = '#securefusion-' + selected_id;
			var nav_id = 'a[ href = "#' + selected_id + '" ]';

			$( nav_id ).addClass( 'nav-tab-active' );
			$( content_id ).removeClass( 'hidden' );
		}

		securefusion_reset_tab_nav();
		securefusion_tab_activate();

		$( '.nav-tab-wrapper > a' ).click( function() {
			securefusion_reset_tab_nav();

			let selected_id = $( this ).attr( 'href' ).split( '#' )[ 1 ];

			securefusion_tab_activate( selected_id );

			setTimeout( function() {
				$( 'input[name="_wp_http_referer"]' ).val( $( location ).attr( 'href' ) );
			}, 100 );
		} );
	} );
} )(jQuery);