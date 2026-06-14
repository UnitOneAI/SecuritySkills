resource "aws_iam_role_policy" "lambda_policy" {
  role = aws_iam_role.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem",
        "dynamodb:PutItem"
      ]
      Resource = aws_dynamodb_table.orders.arn
    }]
  })
}

resource "aws_lambda_permission" "allow_orders_topic" {
  statement_id  = "AllowExecutionFromOrdersTopic"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.worker.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.orders.arn
}
