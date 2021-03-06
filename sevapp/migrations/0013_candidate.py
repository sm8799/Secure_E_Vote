# Generated by Django 3.0.3 on 2020-03-21 11:44

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('sevapp', '0012_poff'),
    ]

    operations = [
        migrations.CreateModel(
            name='Candidate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile_pic', models.ImageField(upload_to='profile')),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='sevapp.Election')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='sevapp.Entry')),
            ],
        ),
    ]
