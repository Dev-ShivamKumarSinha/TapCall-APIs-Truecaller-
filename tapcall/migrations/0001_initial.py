# Generated by Django 2.2.8 on 2022-11-28 19:39

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserContacts',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('phone_number', models.CharField(max_length=15, validators=[django.core.validators.RegexValidator(code='Invalid Phone No.', message='Phone Number should consist on 10 digits', regex='^[0-9]{10}$')])),
                ('email', models.EmailField(max_length=100, null=True)),
                ('spam', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='UserContactMapping',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('userContact', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tapcall.UserContacts')),
            ],
        ),
        migrations.CreateModel(
            name='RegisteredUser',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', models.CharField(max_length=15, unique=True, validators=[django.core.validators.RegexValidator(code='Invalid Phone No.', message='Phone Number should consist on 10 digits', regex='^[0-9]{10}$')])),
                ('email', models.EmailField(max_length=100, null=True)),
                ('spam', models.BooleanField(default=False)),
                ('registeredUser', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]