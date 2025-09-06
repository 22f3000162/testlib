document.addEventListener('DOMContentLoaded', () => {
    // 1) Confirm before deleting a book
    document.querySelectorAll('form.delete-book').forEach(form => {
      form.addEventListener('submit', e => {
        if (!confirm('Are you sure you want to delete this book?')) {
          e.preventDefault();
        }
      });
    });
  
    // 2) Thumbnail preview on add/edit book pages
    const thumbInput = document.querySelector('input[name="thumbnail"]');
    const thumbPreview = document.getElementById('thumbnail-preview');
    if (thumbInput && thumbPreview) {
      thumbInput.addEventListener('change', e => {
        const file = e.target.files[0];
        if (file && file.type.startsWith('image/')) {
          const reader = new FileReader();
          reader.onload = evt => thumbPreview.src = evt.target.result;
          reader.readAsDataURL(file);
        }
      });
    }
  

    // 4) Client-side filter on books page
    const search = document.getElementById('search-books');
    const cards = document.querySelectorAll('.book-card');
    if (search && cards.length) {
      search.addEventListener('input', e => {
        const q = e.target.value.toLowerCase();
        cards.forEach(c => {
          const title = c.querySelector('.title')?.textContent.toLowerCase() || '';
          const author = c.querySelector('.author')?.textContent.toLowerCase() || '';
          c.style.display = (title.includes(q) || author.includes(q)) ? 'block' : 'none';
        });
      });
    }
  });
  