// function to cross out list items
$(document).ready(function () {
    $('.list_one').click(function () {
        if ($(this).hasClass('linethrough')) {
            console.log('clicked');
            $(this).removeClass('linethrough');
        } else {
            $(this).addClass('linethrough');
        }
    });
});
// function to cross out table row items
$(document).ready(function () {
    $('.table_one').click(function () {
        if ($(this).hasClass('linethrough')) {
            console.log('clicked');
            $(this).removeClass('linethrough');
        } else {
            $(this).addClass('linethrough');
        }
    });
});
// return data from tr to python
$(document).ready(function () {
    $('#session_request').click(function () {
        fetch("http://127.0.0.1/session_requests", {
            method: "POST",
            body: JSON.stringify({ user, machines }),

        });
    });
});

// select all buttons
document.querySelector('session_request').forEach(each => {
    // for each one, attach an eventlistener of onclick
    each.onclick = () => {
        // send request to your backend delete url
        fetch("http://127.0.0.1/session_request", {
            method: "POST",
            body: JSON.stringify({ user, machines }),
        });
    };
});