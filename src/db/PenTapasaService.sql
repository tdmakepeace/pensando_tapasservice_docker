CREATE DATABASE IF NOT EXISTS TapAsAService /*!40100 DEFAULT CHARACTER SET latin1 */; 
USE TapAsAService; 
CREATE USER  IF NOT EXISTS 'Pensando'@'%' IDENTIFIED BY 'Pensando0$';
GRANT create, insert, delete, update, select on TapAsAService.* to 'Pensando'@'%' ;
FLUSH privileges;


SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

create table IF NOT EXISTS ActiveTaps
(
	uid bigint auto_increment 
		primary key,
	TapName varchar(100) null,
	TapExpiry datetime null on update CURRENT_TIMESTAMP,
	TapOwner bigint null,
	TapId bigint null
);

create table IF NOT EXISTS TapsAudit
(
	uid bigint auto_increment
		primary key,
  TransTime datetime DEFAULT CURRENT_TIMESTAMP,
  UserId int(11) DEFAULT NULL,
  AdminId int(11) DEFAULT NULL,
  UserName varchar(50) DEFAULT NULL,
  TapUID int(11) DEFAULT NULL,
  TapName varchar(50) DEFAULT NULL,
  WorkloadUID int(11) DEFAULT NULL,
  WorkloadName varchar(50) DEFAULT NULL,
  TapCreated datetime DEFAULT NULL,
  TapDeleted datetime DEFAULT NULL,
  DeletedBy varchar(50) DEFAULT NULL,
  TapActiveId int(11) DEFAULT NULL
);


create table IF NOT EXISTS AdminAccounts
(
	id int auto_increment
		primary key,
	username varchar(50) not null,
	password varchar(255) not null,
	email varchar(100) not null,
	updatedate datetime default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP
)
charset=utf8;

create table IF NOT EXISTS TapOwner
(
	UID bigint auto_increment
		primary key,
	TapUID bigint null,
	OwnerUID bigint null
);

create table IF NOT EXISTS Taps
(
	UID int auto_increment
		primary key,
	Name varchar(50) not null,
	Type varchar(16) null,
	IPaddr bigint null,
	Gateway bigint null,
	Description varchar(50) null,
	StripVlan varchar(3) null,
	PacketSize int null,
	constraint Name_UNIQUE
		unique (Name)
)
charset=latin1;

create table IF NOT EXISTS UserAccounts
(
	id int auto_increment
		primary key,
	username varchar(50) not null,
	password varchar(255) not null,
	email varchar(100) not null,
	updatedate datetime default CURRENT_TIMESTAMP not null on update CURRENT_TIMESTAMP
)
charset=utf8;

create table IF NOT EXISTS WorkloadOwner
(
	UID bigint auto_increment
		primary key,
	WorkloadUID bigint null,
	OwnerUID bigint null
);

create table IF NOT EXISTS Workloads
(
	UID int auto_increment
		primary key,
	Name varchar(50) not null,
	Source1 varchar(100) null,
	Source2 varchar(100) null,
	Destin1 varchar(100) null,
	Destin2 varchar(100) null,
	Prot1 varchar(100) null,
	Prot2 varchar(100) null,
	Description varchar(50) null,
	constraint Name_UNIQUE
		unique (Name)
)
charset=latin1;




INSERT INTO `AdminAccounts` (`id`, `username`, `password`, `email`) VALUES (1, 'admin', 'pbkdf2:sha256:150000$BeAI78rv$45b17e8da897e6855b5aa1b2f205fb6311ed740e88b6f9c82fa23b0b3984b4ab', 'support@pensando.io');

