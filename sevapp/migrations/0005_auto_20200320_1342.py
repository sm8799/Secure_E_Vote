# Generated by Django 3.0.3 on 2020-03-20 13:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('sevapp', '0004_auto_20200320_0629'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='poff',
            name='election',
        ),
        migrations.RemoveField(
            model_name='voter',
            name='election',
        ),
        migrations.DeleteModel(
            name='Candidate',
        ),
        migrations.DeleteModel(
            name='Election',
        ),
        migrations.DeleteModel(
            name='Poff',
        ),
        migrations.DeleteModel(
            name='Voter',
        ),
    ]
