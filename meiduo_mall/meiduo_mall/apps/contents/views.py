from django.shortcuts import render, redirect

# Create your views here.
from django.urls import reverse
from django.views import View


class IndexView(View):
    def get(self,request):
        return render(request,'index.html')