// function to cross out list items
$(document).ready(function() {
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
$(document).ready(function() {
    $('.table_one').click(function () {
        if ($(this).hasClass('linethrough')) {
            console.log('clicked');
            $(this).removeClass('linethrough');
        } else {
            $(this).addClass('linethrough');
        }
    });
});