import requests

def verify_payment(reference):
    """Verifies payment with Paystack using the transaction reference."""
    paystack_secret_key = 'your_paystack_secret_key'  # Replace with your Paystack secret key
    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {
        "Authorization": f"Bearer {paystack_secret_key}",
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()  # Return the JSON response from Paystack
    else:
        response.raise_for_status()  # Raise an exception for HTTP errors




# def handle_payment(request, application):
#     """Handles payment details submission and linking to the application."""
#     payment_reference = request.data.get('reference')
#     payment_amount = request.data.get('amount')
#     transaction_id = request.data.get('transaction_id')

#     if not payment_reference or not payment_amount:
#         return Response(format_error_response(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             error_code="PAYMENT_ERROR",
#             message="Payment details are required."
#         ), status=status.HTTP_400_BAD_REQUEST)

#     # Verify payment with Paystack
#     try:
#         verification_response = verify_payment(payment_reference)
#         if verification_response['data']['status'] != 'success':
#             return Response(format_error_response(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 error_code="PAYMENT_VERIFICATION_FAILED",
#                 message="Payment verification failed."
#             ), status=status.HTTP_400_BAD_REQUEST)
#     except requests.exceptions.RequestException as e:
#         return Response(format_error_response(
#             status_code=status.HTTP_502_BAD_GATEWAY,
#             error_code="PAYMENT_VERIFICATION_ERROR",
#             message="There was an error verifying the payment.",
#             details=str(e)
#         ), status=status.HTTP_502_BAD_GATEWAY)

#     # Create payment record
#     Payment.objects.create(
#         user=request.user,
#         application=application,
#         transaction_id=transaction_id,
#         reference=payment_reference,
#         amount=payment_amount,
#         status='COMPLETED'
#     )