/*
    Thanks, Stack Exchange:
    https://wordpress.stackexchange.com/questions/235406/how-do-i-select-an-image-from-media-library-in-my-plugins
 */
jQuery(document).ready(function ($) {
    jQuery('input#openid_media_manager').click(function (e) {
        e.preventDefault();
        let image_frame;
        if (image_frame) {
            image_frame.open();
        }

        // Define image_frame as wp.media object
        image_frame = wp.media({
            title: 'Select Media',
            multiple: false,
            library: {
                type: 'image',
            }
        });

        image_frame.on('close', function () {
            // On close, get selections and save to the hidden input
            // plus other AJAX stuff to refresh the image preview
            const selection = image_frame.state().get('selection');
            const gallery_ids = [];
            let my_index = 0;
            selection.each(function (attachment) {
                gallery_ids[my_index] = attachment['id'];
                my_index++;
            });
            const ids = gallery_ids.join(",");
            if (ids.length === 0) return true;//if closed without selecting an image
            jQuery('input#openid_login_image_id').val(ids);

            // Update the preview image
            jQuery('img#openid_image_preview').attr('src', selection.models[0].attributes.url)
        });

        image_frame.on('open', function () {
            var selection = image_frame.state().get('selection');
            var ids = jQuery('input#openid_login_image_id').val().split(',');
            ids.forEach(function (id) {
                var attachment = wp.media.attachment(id);
                attachment.fetch();
                selection.add(attachment ? [attachment] : []);
            });

        });

        image_frame.open();
    });

    jQuery('input#openid_remove_image').click(function (e) {
        // Get the default image from the button
        e.preventDefault();
        // Clear the input
        jQuery('input#openid_login_image_id').val('');

        // Update the preview image
        const img = jQuery('img#openid_image_preview');
        img.attr('src', img.data('default-image'));
    });

});
