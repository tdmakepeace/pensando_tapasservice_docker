# Docker image for tap as a service demo

# To deploy
The following line will deploy the container.<br><br>
_sudo docker run -d -p \<Listining Port\>:5000 -v \<local folder\>:/app/PenTapasaService tdmakepeace/pentapasaservice_docker_<br><br>

The options to edit are the \<Listining Port\> example would be port 5000 and the \<local folder\> <br>
The local folder is used to maintain all the files from the container that you want to be persistent. 
Things like the database folder, and the variables file.<br><br>

Example: <br>
_cd /home/user_<br>
_mkdir PenTapasaService_<br>
_sudo docker run -d -p 5000:5000 -v /home/user/PenTapasaService:/app/PenTapasaService tdmakepeace/pentapasaservice_docker_<br>
<br>
**Check Running** <br>
_tail -f PenTapasaService/debug.txt_<br>
<br>

<br><br>
**Using a Docker Volume** <br>
Another option is to create and use a docker volume, this is recommended<br>
_sudo docker volume create pentap_data_<br>
_sudo docker run -d -p 5000:5000 -v pentap_data:/app/PenTapasaService tdmakepeace/pentapasaservice_docker_<br>
<br>

# Useful docker commands.

**get contianer id's**  - sudo docker ps<br>
**stop the container** - sudo docker stop \<container id\><br>
**start the container** - sudo docker start \<container id\><br>
**set container to survice a reboot** - sudo docker update --restart=always \<container id\><br>


# Disclaimer
This software is provided without support, warranty, or guarantee. Use at your own risk.
