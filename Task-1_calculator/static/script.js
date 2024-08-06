document.addEventListener('DOMContentLoaded', function() {
    
    //display element
    let display = document.getElementById('display');

    //function to display the input and output
    window.cbutton = function(number) {
        display.value += number;
    };

    // function for the clear button
    window.clearDisplay = function() {
        display.value = '';
    };

    // send the calculation request to the py server and gets back the result
    window.calculate = function() {
       
        let expression = display.value;

        // post request for calculations
        fetch('/calculate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ expression: expression })
        })
        .then(response => response.json())
        .then(data => {
            display.value = data.result;
        })
        .catch(error => {
                //display error to console incase of any errors 

            console.error('Error:', error);
        });
    };
});
