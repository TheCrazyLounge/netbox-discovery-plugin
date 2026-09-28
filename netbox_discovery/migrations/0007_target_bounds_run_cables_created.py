import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_discovery", "0006_macaddresstableentry"),
    ]

    operations = [
        migrations.AddField(
            model_name="discoveryrun",
            name="cables_created",
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="discoverytarget",
            name="max_depth",
            field=models.PositiveIntegerField(
                default=3,
                help_text="Maximum CDP/LLDP neighbor recursion depth.",
                validators=[django.core.validators.MaxValueValidator(10)],
            ),
        ),
        migrations.AlterField(
            model_name="discoverytarget",
            name="ssh_timeout",
            field=models.PositiveIntegerField(
                default=10,
                help_text="SSH connection timeout in seconds.",
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(120),
                ],
            ),
        ),
        migrations.AlterField(
            model_name="discoverytarget",
            name="max_workers",
            field=models.PositiveIntegerField(
                default=5,
                help_text="Number of devices to crawl in parallel. Increase for faster discovery on large networks.",
                validators=[
                    django.core.validators.MinValueValidator(1),
                    django.core.validators.MaxValueValidator(50),
                ],
            ),
        ),
    ]
