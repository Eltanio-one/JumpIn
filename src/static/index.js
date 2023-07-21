$(document).ready(function () {
    var colours = ['aquamarine', 'indigo', 'lightsalmon', 'yellowgreen', 'seagreen', 'darkkhaki', 'darkolivegreen', 'tomato', 'salmon', 'peru'];

    var randomColour = colours[Math.floor(Math.random() * colours.length)];

    $('#index_welcome').css({
        'color': randomColour
    });
});