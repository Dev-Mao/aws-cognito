const shoppingCartIcon = document.getElementById("icon-shopping-cart");
const shoppingCartContainer = document.getElementById(
  "icon-shopping-cart-container"
);
const shoppingCart = document.getElementById("shopping-cart");
const products = document.getElementById("products-section");
const iconExit = document.getElementById("icon-exit");
const selectedProducts = document.getElementsByClassName("product-container");
const buyButton = document.getElementById("buy-button");

shoppingCartIcon.addEventListener("click", function () {
  shoppingCart.style.display = "flex";
  products.style.display = "none";
  shoppingCartContainer.style.display = "none";
  iconExit.style.display = "block";
  fillCart();
});

iconExit.addEventListener("click", function () {
  shoppingCart.style.display = "none";
  products.style.display = "flex";
  iconExit.style.display = "none";
  shoppingCartContainer.style.display = "flex";
  getProductsNumber();
});

let cart = [];

function addToCart(product) {
  const value = product.getAttribute("data-product");
  cart.push(JSON.parse(value));
  getProductsNumber();
}

function getProductsNumber() {
  const productsNumber = document.getElementById("number-of-products");
  productsNumber.textContent = cart.length;
}

function removeFromCart(itemName) {
  const index = cart.findIndex(
    (productInCart) => productInCart.name === itemName
  );
  if (index !== -1) {
    cart.splice(index, 1);
  }
  fillCart();
}

[...selectedProducts].forEach((product) => {
  product.addEventListener("click", () => addToCart(product));
});

function fillCart() {
  if (cart.length > 0) {
    const itemsContainer = document.querySelector(".items-container");
    const totalValue = document.getElementById("total-value");
    let totalSum = 0;
    itemsContainer.innerHTML = "";
    cart.forEach((item) => {
      const product = `<div class="item-container">    
                        <span>${item.name}</span>
                        <span>$${item.price}</span>
                        <img class="remove-icon" id="remove-icon" src="https://img.icons8.com/material-sharp/48/trash.png"></img>
                      </div>`;
      itemsContainer.insertAdjacentHTML("beforeend", product);
      totalSum += item.price;
    });
    totalValue.textContent = `Total: $${totalSum}`;
  }
}

document.addEventListener("click", (event) => {
  if (event.target.classList.contains("remove-icon")) {
    const parentItem = event.target.closest(".item-container");
    const itemName = parentItem.querySelector("span:first-child").textContent;
    removeFromCart(itemName);
  }
});

buyButton.addEventListener("click", function () {
  window.open("https://wa.link/4niq4z");
});
