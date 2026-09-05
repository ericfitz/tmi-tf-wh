# Certificate + DNS for the shared webhook hostname. This repo creates them as
# the first tenant; move them to a shared stack when a second webhook app exists.

resource "aws_acm_certificate" "webhook" {
  domain_name       = var.hostname
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for dvo in aws_acm_certificate.webhook.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id         = data.aws_route53_zone.this.zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "webhook" {
  certificate_arn         = aws_acm_certificate.webhook.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

resource "aws_route53_record" "webhook" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = var.hostname
  type    = "CNAME"
  ttl     = 300
  records = [kubernetes_ingress_v1.this.status[0].load_balancer[0].ingress[0].hostname]
}
