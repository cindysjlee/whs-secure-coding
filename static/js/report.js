const targetType = document.getElementById('target_type');
const userTarget = document.getElementById('user_target');
const productTarget = document.getElementById('product_target');

const userSelect = document.getElementById('user_id');
const productSelect = document.getElementById('product_id');
const targetId = document.getElementById('target_id');

function updateTargetFields() {
  targetId.value = '';

  if (targetType.value === 'user') {
    userTarget.classList.remove('hidden');
    productTarget.classList.add('hidden');

    productSelect.value = '';
  } else if (targetType.value === 'product') {
    userTarget.classList.add('hidden');
    productTarget.classList.remove('hidden');

    userSelect.value = '';
  } else {
    userTarget.classList.add('hidden');
    productTarget.classList.add('hidden');

    userSelect.value = '';
    productSelect.value = '';
  }
}

targetType.addEventListener('change', updateTargetFields);

userSelect.addEventListener('change', function() {
  targetId.value = userSelect.value;
});

productSelect.addEventListener('change', function() {
  targetId.value = productSelect.value;
});

updateTargetFields();