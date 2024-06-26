USE [master]
GO
/****** Object:  Database [ruoyi]    Script Date: 2024-03-23 09:52:19 ******/
CREATE DATABASE [ruoyi]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'ruoyi', FILENAME = N'D:\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\ruoyi.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'ruoyi_log', FILENAME = N'D:\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\DATA\ruoyi_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
GO
ALTER DATABASE [ruoyi] SET COMPATIBILITY_LEVEL = 140
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [ruoyi].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [ruoyi] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [ruoyi] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [ruoyi] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [ruoyi] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [ruoyi] SET ARITHABORT OFF 
GO
ALTER DATABASE [ruoyi] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [ruoyi] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [ruoyi] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [ruoyi] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [ruoyi] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [ruoyi] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [ruoyi] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [ruoyi] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [ruoyi] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [ruoyi] SET  DISABLE_BROKER 
GO
ALTER DATABASE [ruoyi] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [ruoyi] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [ruoyi] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [ruoyi] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [ruoyi] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [ruoyi] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [ruoyi] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [ruoyi] SET RECOVERY FULL 
GO
ALTER DATABASE [ruoyi] SET  MULTI_USER 
GO
ALTER DATABASE [ruoyi] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [ruoyi] SET DB_CHAINING OFF 
GO
ALTER DATABASE [ruoyi] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [ruoyi] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [ruoyi] SET DELAYED_DURABILITY = DISABLED 
GO
EXEC sys.sp_db_vardecimal_storage_format N'ruoyi', N'ON'
GO
ALTER DATABASE [ruoyi] SET QUERY_STORE = OFF
GO
USE [ruoyi]
GO
/****** Object:  Table [dbo].[gen_table]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[gen_table](
	[table_id] [bigint] IDENTITY(1,1) NOT NULL,
	[table_name] [nvarchar](200) NULL,
	[table_comment] [nvarchar](500) NULL,
	[sub_table_name] [nvarchar](64) NULL,
	[sub_table_fk_name] [nvarchar](64) NULL,
	[class_name] [nvarchar](100) NULL,
	[tpl_web_type] [nvarchar](30) NULL,
	[tpl_category] [nvarchar](200) NULL,
	[package_name] [nvarchar](100) NULL,
	[module_name] [nvarchar](30) NULL,
	[business_name] [nvarchar](30) NULL,
	[function_name] [nvarchar](50) NULL,
	[function_author] [nvarchar](50) NULL,
	[gen_type] [char](1) NULL,
	[gen_path] [nvarchar](200) NULL,
	[options] [nvarchar](1000) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
 CONSTRAINT [PK_gen_table] PRIMARY KEY CLUSTERED 
(
	[table_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[gen_table_column]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[gen_table_column](
	[column_id] [bigint] IDENTITY(1,1) NOT NULL,
	[table_id] [bigint] NULL,
	[column_name] [nvarchar](200) NULL,
	[column_comment] [nvarchar](500) NULL,
	[column_type] [nvarchar](100) NULL,
	[java_type] [nvarchar](500) NULL,
	[java_field] [nvarchar](200) NULL,
	[is_pk] [char](1) NULL,
	[is_increment] [char](1) NULL,
	[is_required] [char](1) NULL,
	[is_insert] [char](1) NULL,
	[is_edit] [char](1) NULL,
	[is_list] [char](1) NULL,
	[is_query] [char](1) NULL,
	[query_type] [nvarchar](200) NULL,
	[html_type] [nvarchar](200) NULL,
	[dict_type] [nvarchar](200) NULL,
	[sort] [int] NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
 CONSTRAINT [PK_gen_table_column] PRIMARY KEY CLUSTERED 
(
	[column_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_blob_triggers]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_blob_triggers](
	[sched_name] [nvarchar](120) NOT NULL,
	[trigger_name] [nvarchar](120) NOT NULL,
	[trigger_group] [nvarchar](120) NOT NULL,
	[blob_data] [varbinary](max) NULL,
 CONSTRAINT [PK_qrtz_blob_triggers] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[trigger_name] ASC,
	[trigger_group] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_calendars]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_calendars](
	[sched_name] [nvarchar](120) NOT NULL,
	[calendar_name] [nvarchar](200) NOT NULL,
	[calendar] [varbinary](max) NOT NULL,
 CONSTRAINT [PK_qrtz_calendars] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[calendar_name] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_cron_triggers]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_cron_triggers](
	[sched_name] [nvarchar](120) NOT NULL,
	[trigger_name] [nvarchar](120) NOT NULL,
	[trigger_group] [nvarchar](120) NOT NULL,
	[cron_expression] [nvarchar](200) NOT NULL,
	[time_zone_id] [nvarchar](80) NULL,
 CONSTRAINT [PK_qrtz_cron_triggers] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[trigger_name] ASC,
	[trigger_group] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_fired_triggers]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_fired_triggers](
	[sched_name] [nvarchar](120) NOT NULL,
	[entry_id] [nvarchar](95) NOT NULL,
	[trigger_name] [nvarchar](200) NOT NULL,
	[trigger_group] [nvarchar](200) NOT NULL,
	[instance_name] [nvarchar](200) NOT NULL,
	[fired_time] [bigint] NOT NULL,
	[sched_time] [bigint] NOT NULL,
	[priority] [int] NOT NULL,
	[state] [nvarchar](16) NOT NULL,
	[job_name] [nvarchar](200) NULL,
	[job_group] [nvarchar](200) NULL,
	[is_nonconcurrent] [nvarchar](1) NULL,
	[requests_recovery] [nvarchar](1) NULL,
 CONSTRAINT [PK_qrtz_fired_triggers] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[entry_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_job_details]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_job_details](
	[sched_name] [nvarchar](120) NOT NULL,
	[job_name] [nvarchar](120) NOT NULL,
	[job_group] [nvarchar](120) NOT NULL,
	[description] [nvarchar](250) NULL,
	[job_class_name] [nvarchar](250) NOT NULL,
	[is_durable] [nvarchar](1) NOT NULL,
	[is_nonconcurrent] [nvarchar](1) NOT NULL,
	[is_update_data] [nvarchar](1) NOT NULL,
	[requests_recovery] [nvarchar](1) NOT NULL,
	[job_data] [varbinary](max) NULL,
 CONSTRAINT [PK_qrtz_job_details] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[job_name] ASC,
	[job_group] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_locks]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_locks](
	[sched_name] [nvarchar](120) NOT NULL,
	[lock_name] [nvarchar](40) NOT NULL,
 CONSTRAINT [PK_qrtz_locks] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[lock_name] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_paused_trigger_grps]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_paused_trigger_grps](
	[sched_name] [nvarchar](120) NOT NULL,
	[trigger_group] [nvarchar](200) NOT NULL,
 CONSTRAINT [PK_qrtz_paused_trigger_grps] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[trigger_group] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_scheduler_state]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_scheduler_state](
	[sched_name] [nvarchar](120) NOT NULL,
	[instance_name] [nvarchar](200) NOT NULL,
	[last_checkin_time] [bigint] NOT NULL,
	[checkin_interval] [bigint] NOT NULL,
 CONSTRAINT [PK_qrtz_scheduler_state] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[instance_name] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_simple_triggers]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_simple_triggers](
	[sched_name] [nvarchar](120) NOT NULL,
	[trigger_name] [nvarchar](120) NOT NULL,
	[trigger_group] [nvarchar](120) NOT NULL,
	[repeat_count] [bigint] NOT NULL,
	[repeat_interval] [bigint] NOT NULL,
	[times_triggered] [bigint] NOT NULL,
 CONSTRAINT [PK_qrtz_simple_triggers] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[trigger_name] ASC,
	[trigger_group] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_simprop_triggers]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_simprop_triggers](
	[sched_name] [nvarchar](120) NOT NULL,
	[trigger_name] [nvarchar](120) NOT NULL,
	[trigger_group] [nvarchar](120) NOT NULL,
	[str_prop_1] [nvarchar](512) NULL,
	[str_prop_2] [nvarchar](512) NULL,
	[str_prop_3] [nvarchar](512) NULL,
	[int_prop_1] [int] NULL,
	[int_prop_2] [int] NULL,
	[long_prop_1] [bigint] NULL,
	[long_prop_2] [bigint] NULL,
	[dec_prop_1] [decimal](13, 4) NULL,
	[dec_prop_2] [decimal](13, 4) NULL,
	[bool_prop_1] [nvarchar](1) NULL,
	[bool_prop_2] [nvarchar](1) NULL,
 CONSTRAINT [PK_qrtz_simprop_triggers] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[trigger_name] ASC,
	[trigger_group] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[qrtz_triggers]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[qrtz_triggers](
	[sched_name] [nvarchar](120) NOT NULL,
	[trigger_name] [nvarchar](120) NOT NULL,
	[trigger_group] [nvarchar](120) NOT NULL,
	[job_name] [nvarchar](120) NOT NULL,
	[job_group] [nvarchar](120) NOT NULL,
	[description] [nvarchar](250) NULL,
	[next_fire_time] [bigint] NULL,
	[prev_fire_time] [bigint] NULL,
	[priority] [int] NULL,
	[trigger_state] [nvarchar](16) NOT NULL,
	[trigger_type] [nvarchar](8) NOT NULL,
	[start_time] [bigint] NOT NULL,
	[end_time] [bigint] NULL,
	[calendar_name] [nvarchar](200) NULL,
	[misfire_instr] [smallint] NULL,
	[job_data] [varbinary](max) NULL,
 CONSTRAINT [PK_qrtz_triggers] PRIMARY KEY CLUSTERED 
(
	[sched_name] ASC,
	[trigger_name] ASC,
	[trigger_group] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_config]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_config](
	[config_id] [int] IDENTITY(1,1) NOT NULL,
	[config_name] [nvarchar](100) NULL,
	[config_key] [nvarchar](100) NULL,
	[config_value] [nvarchar](500) NULL,
	[config_type] [char](1) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
PRIMARY KEY CLUSTERED 
(
	[config_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_dept]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_dept](
	[dept_id] [bigint] IDENTITY(1,1) NOT NULL,
	[parent_id] [bigint] NULL,
	[ancestors] [nvarchar](50) NULL,
	[dept_name] [nvarchar](50) NULL,
	[order_num] [int] NULL,
	[leader] [nvarchar](50) NULL,
	[phone] [nvarchar](50) NULL,
	[email] [nvarchar](50) NULL,
	[company_id] [bigint] NULL,
	[status] [char](1) NULL,
	[del_flag] [char](1) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
 CONSTRAINT [PK__sys_dept__DCA659748A884CE3] PRIMARY KEY CLUSTERED 
(
	[dept_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_dict_data]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_dict_data](
	[dict_code] [bigint] IDENTITY(1,1) NOT NULL,
	[dict_sort] [int] NULL,
	[dict_label] [nvarchar](100) NULL,
	[dict_value] [nvarchar](100) NULL,
	[dict_type] [nvarchar](100) NULL,
	[css_class] [nvarchar](100) NULL,
	[list_class] [nvarchar](100) NULL,
	[is_default] [char](1) NULL,
	[status] [char](1) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
PRIMARY KEY CLUSTERED 
(
	[dict_code] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_dict_type]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_dict_type](
	[dict_id] [bigint] IDENTITY(1,1) NOT NULL,
	[dict_name] [nvarchar](100) NULL,
	[dict_type] [nvarchar](100) NULL,
	[status] [char](1) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
PRIMARY KEY CLUSTERED 
(
	[dict_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_job]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_job](
	[job_id] [bigint] IDENTITY(1,1) NOT NULL,
	[job_name] [nvarchar](64) NOT NULL,
	[job_group] [nvarchar](64) NOT NULL,
	[invoke_target] [nvarchar](500) NOT NULL,
	[cron_expression] [nvarchar](255) NULL,
	[misfire_policy] [nvarchar](20) NULL,
	[concurrent] [char](1) NULL,
	[status] [char](1) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
 CONSTRAINT [PK_sys_job] PRIMARY KEY CLUSTERED 
(
	[job_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_job_log]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_job_log](
	[job_log_id] [bigint] IDENTITY(1,1) NOT NULL,
	[job_name] [nvarchar](64) NOT NULL,
	[job_group] [nvarchar](64) NOT NULL,
	[invoke_target] [nvarchar](500) NOT NULL,
	[job_message] [nvarchar](500) NULL,
	[status] [char](1) NULL,
	[exception_info] [nvarchar](2000) NULL,
	[create_time] [datetime] NULL,
PRIMARY KEY CLUSTERED 
(
	[job_log_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_logininfor]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_logininfor](
	[info_id] [bigint] IDENTITY(1,1) NOT NULL,
	[user_name] [nvarchar](50) NULL,
	[ipaddr] [nvarchar](128) NULL,
	[login_location] [nvarchar](255) NULL,
	[browser] [nvarchar](50) NULL,
	[os] [nvarchar](50) NULL,
	[status] [char](1) NULL,
	[msg] [nvarchar](255) NULL,
	[login_time] [datetime] NULL,
PRIMARY KEY CLUSTERED 
(
	[info_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_menu]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_menu](
	[menu_id] [bigint] IDENTITY(1,1) NOT NULL,
	[menu_name] [nvarchar](50) NOT NULL,
	[parent_id] [bigint] NULL,
	[order_num] [int] NULL,
	[path] [nvarchar](200) NULL,
	[component] [nvarchar](255) NULL,
	[query] [nvarchar](255) NULL,
	[is_frame] [int] NULL,
	[is_cache] [int] NULL,
	[menu_type] [char](1) NULL,
	[visible] [char](1) NULL,
	[status] [char](1) NULL,
	[perms] [nvarchar](100) NULL,
	[icon] [nvarchar](100) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
PRIMARY KEY CLUSTERED 
(
	[menu_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_notice]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_notice](
	[notice_id] [int] IDENTITY(1,1) NOT NULL,
	[notice_title] [nvarchar](50) NOT NULL,
	[notice_type] [char](1) NOT NULL,
	[notice_content] [varbinary](max) NULL,
	[status] [char](1) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[notice_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_oper_log]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_oper_log](
	[oper_id] [bigint] IDENTITY(1,1) NOT NULL,
	[title] [nvarchar](50) NULL,
	[business_type] [int] NULL,
	[method] [nvarchar](100) NULL,
	[request_method] [nvarchar](10) NULL,
	[operator_type] [int] NULL,
	[oper_name] [nvarchar](50) NULL,
	[dept_name] [nvarchar](50) NULL,
	[oper_url] [nvarchar](255) NULL,
	[oper_ip] [nvarchar](128) NULL,
	[oper_location] [nvarchar](255) NULL,
	[oper_param] [nvarchar](2000) NULL,
	[json_result] [nvarchar](2000) NULL,
	[status] [int] NULL,
	[error_msg] [nvarchar](2000) NULL,
	[oper_time] [datetime] NULL,
	[cost_time] [bigint] NULL,
PRIMARY KEY CLUSTERED 
(
	[oper_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_post]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_post](
	[post_id] [bigint] IDENTITY(1,1) NOT NULL,
	[post_code] [nvarchar](64) NOT NULL,
	[post_name] [nvarchar](50) NOT NULL,
	[post_sort] [int] NOT NULL,
	[status] [char](1) NOT NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
PRIMARY KEY CLUSTERED 
(
	[post_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_role]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_role](
	[role_id] [bigint] IDENTITY(1,1) NOT NULL,
	[role_name] [nvarchar](30) NOT NULL,
	[role_key] [nvarchar](100) NOT NULL,
	[role_sort] [int] NOT NULL,
	[data_scope] [char](1) NULL,
	[menu_check_strictly] [tinyint] NULL,
	[dept_check_strictly] [tinyint] NULL,
	[status] [char](1) NOT NULL,
	[del_flag] [char](1) NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
PRIMARY KEY CLUSTERED 
(
	[role_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_role_dept]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_role_dept](
	[role_id] [bigint] NOT NULL,
	[dept_id] [bigint] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[role_id] ASC,
	[dept_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_role_menu]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_role_menu](
	[role_id] [bigint] NOT NULL,
	[menu_id] [bigint] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[role_id] ASC,
	[menu_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_user]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_user](
	[user_id] [bigint] IDENTITY(1,1) NOT NULL,
	[dept_id] [bigint] NULL,
	[user_name] [nvarchar](30) NOT NULL,
	[nick_name] [nvarchar](30) NOT NULL,
	[user_type] [nvarchar](2) NULL,
	[email] [nvarchar](50) NULL,
	[phonenumber] [nvarchar](11) NULL,
	[sex] [char](1) NULL,
	[avatar] [nvarchar](100) NULL,
	[password] [nvarchar](100) NULL,
	[status] [char](1) NULL,
	[del_flag] [char](1) NULL,
	[login_ip] [nvarchar](128) NULL,
	[login_date] [datetime] NULL,
	[create_by] [nvarchar](64) NULL,
	[create_time] [datetime] NULL,
	[update_by] [nvarchar](64) NULL,
	[update_time] [datetime] NULL,
	[remark] [nvarchar](500) NULL,
PRIMARY KEY CLUSTERED 
(
	[user_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_user_post]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_user_post](
	[user_id] [bigint] NOT NULL,
	[post_id] [bigint] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[user_id] ASC,
	[post_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[sys_user_role]    Script Date: 2024-03-23 09:52:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[sys_user_role](
	[user_id] [bigint] NOT NULL,
	[role_id] [bigint] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[user_id] ASC,
	[role_id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[gen_table] ON 

INSERT [dbo].[gen_table] ([table_id], [table_name], [table_comment], [sub_table_name], [sub_table_fk_name], [class_name], [tpl_web_type], [tpl_category], [package_name], [module_name], [business_name], [function_name], [function_author], [gen_type], [gen_path], [options], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (3, N'sys_user', N'用户表', N'', N'', N'SysUser', N'element-ui', N'crud', N'com.ruoyi.system', N'system', N'user', N'用户', N'ruoyi', NULL, NULL, N'{}', N'admin', CAST(N'2024-03-23T09:24:12.183' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.460' AS DateTime), NULL)
SET IDENTITY_INSERT [dbo].[gen_table] OFF
GO
SET IDENTITY_INSERT [dbo].[gen_table_column] ON 

INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (9, 3, N'user_id', N'用户ID', N'bigint', N'Long', N'userId', N'1', N'1', N'1', N'1', NULL, NULL, NULL, N'EQ', N'input', NULL, 1, N'admin', CAST(N'2024-03-23T09:24:12.350' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.473' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (10, 3, N'dept_id', N'部门ID', N'bigint', N'Long', N'deptId', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'input', NULL, 2, N'admin', CAST(N'2024-03-23T09:24:12.353' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.480' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (11, 3, N'user_name', N'用户账号', N'nvarchar', N'String', N'userName', N'0', N'0', N'1', N'1', N'1', N'1', N'1', N'LIKE', N'input', NULL, 3, N'admin', CAST(N'2024-03-23T09:24:12.360' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.480' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (12, 3, N'nick_name', N'用户昵称', N'nvarchar', N'String', N'nickName', N'0', N'0', N'1', N'1', N'1', N'1', N'1', N'LIKE', N'input', NULL, 4, N'admin', CAST(N'2024-03-23T09:24:12.360' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.483' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (13, 3, N'user_type', N'用户类型（00系统用户）', N'nvarchar', N'String', N'userType', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'select', NULL, 5, N'admin', CAST(N'2024-03-23T09:24:12.363' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.483' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (14, 3, N'email', N'用户邮箱', N'nvarchar', N'String', N'email', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'input', NULL, 6, N'admin', CAST(N'2024-03-23T09:24:12.367' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.490' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (15, 3, N'phonenumber', N'手机号码', N'nvarchar', N'String', N'phonenumber', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'input', NULL, 7, N'admin', CAST(N'2024-03-23T09:24:12.370' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.490' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (16, 3, N'sex', N'用户性别（0男 1女 2未知）', N'char', N'String', N'sex', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'select', NULL, 8, N'admin', CAST(N'2024-03-23T09:24:12.370' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.493' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (17, 3, N'avatar', N'头像地址', N'nvarchar', N'String', N'avatar', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'input', NULL, 9, N'admin', CAST(N'2024-03-23T09:24:12.373' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.497' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (18, 3, N'password', N'密码', N'nvarchar', N'String', N'password', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'input', NULL, 10, N'admin', CAST(N'2024-03-23T09:24:12.377' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.500' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (19, 3, N'status', N'帐号状态（0正常 1停用）', N'char', N'String', N'status', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'radio', NULL, 11, N'admin', CAST(N'2024-03-23T09:24:12.380' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.500' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (20, 3, N'del_flag', N'删除标志（0代表存在 2代表删除）', N'char', N'String', N'delFlag', N'0', N'0', N'0', N'1', NULL, NULL, NULL, N'EQ', N'input', NULL, 12, N'admin', CAST(N'2024-03-23T09:24:12.380' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.503' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (21, 3, N'login_ip', N'最后登录IP', N'nvarchar', N'String', N'loginIp', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'input', NULL, 13, N'admin', CAST(N'2024-03-23T09:24:12.383' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.503' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (22, 3, N'login_date', N'最后登录时间', N'datetime', N'Date', N'loginDate', N'0', N'0', N'0', N'1', N'1', N'1', N'1', N'EQ', N'datetime', NULL, 14, N'admin', CAST(N'2024-03-23T09:24:12.387' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.507' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (23, 3, N'create_by', N'创建者', N'nvarchar', N'String', N'createBy', N'0', N'0', N'0', N'1', NULL, NULL, NULL, N'EQ', N'input', NULL, 15, N'admin', CAST(N'2024-03-23T09:24:12.390' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.507' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (24, 3, N'create_time', N'创建时间', N'datetime', N'Date', N'createTime', N'0', N'0', N'0', N'1', NULL, NULL, NULL, N'EQ', N'datetime', NULL, 16, N'admin', CAST(N'2024-03-23T09:24:12.390' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.510' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (25, 3, N'update_by', N'更新者', N'nvarchar', N'String', N'updateBy', N'0', N'0', N'0', N'1', N'1', NULL, NULL, N'EQ', N'input', NULL, 17, N'admin', CAST(N'2024-03-23T09:24:12.393' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.513' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (26, 3, N'update_time', N'更新时间', N'datetime', N'Date', N'updateTime', N'0', N'0', N'0', N'1', N'1', NULL, NULL, N'EQ', N'datetime', NULL, 18, N'admin', CAST(N'2024-03-23T09:24:12.397' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.513' AS DateTime))
INSERT [dbo].[gen_table_column] ([column_id], [table_id], [column_name], [column_comment], [column_type], [java_type], [java_field], [is_pk], [is_increment], [is_required], [is_insert], [is_edit], [is_list], [is_query], [query_type], [html_type], [dict_type], [sort], [create_by], [create_time], [update_by], [update_time]) VALUES (27, 3, N'remark', N'备注', N'nvarchar', N'String', N'remark', N'0', N'0', N'0', N'1', N'1', N'1', NULL, N'EQ', N'input', NULL, 19, N'admin', CAST(N'2024-03-23T09:24:12.400' AS DateTime), NULL, CAST(N'2024-03-23T09:24:54.520' AS DateTime))
SET IDENTITY_INSERT [dbo].[gen_table_column] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_config] ON 

INSERT [dbo].[sys_config] ([config_id], [config_name], [config_key], [config_value], [config_type], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, N'主框架页-默认皮肤样式名称', N'sys.index.skinName', N'skin-blue', N'Y', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'蓝色 skin-blue、绿色 skin-green、紫色 skin-purple、红色 skin-red、黄色 skin-yellow')
INSERT [dbo].[sys_config] ([config_id], [config_name], [config_key], [config_value], [config_type], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, N'用户管理-账号初始密码', N'sys.user.initPassword', N'123456', N'Y', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'初始化密码 123456')
INSERT [dbo].[sys_config] ([config_id], [config_name], [config_key], [config_value], [config_type], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (3, N'主框架页-侧边栏主题', N'sys.index.sideTheme', N'theme-dark', N'Y', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'深色主题theme-dark，浅色主题theme-light')
INSERT [dbo].[sys_config] ([config_id], [config_name], [config_key], [config_value], [config_type], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (4, N'账号自助-验证码开关', N'sys.account.captchaEnabled', N'true', N'Y', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2023-09-23T14:32:02.000' AS DateTime), N'是否开启验证码功能（true开启，false关闭）')
INSERT [dbo].[sys_config] ([config_id], [config_name], [config_key], [config_value], [config_type], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (5, N'账号自助-是否开启用户注册功能', N'sys.account.registerUser', N'false', N'Y', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'是否开启注册用户功能（true开启，false关闭）')
INSERT [dbo].[sys_config] ([config_id], [config_name], [config_key], [config_value], [config_type], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (6, N'用户登录-黑名单列表', N'sys.login.blackIPList', N'', N'Y', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'设置登录IP黑名单限制，多个匹配项以;分隔，支持匹配（*通配、网段）')
SET IDENTITY_INSERT [dbo].[sys_config] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_dept] ON 

INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (100, 0, N'0', N'XX集团', 10, N'若依', N'15888888888', N'ry@qq.com', 5, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-02T14:12:25.000' AS DateTime))
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (101, 100, N'0,100', N'XXA有限公司', 10, N'', N'', N'', 1, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-15T16:04:42.000' AS DateTime))
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (102, 100, N'0,100', N'XXB有限公司', 10, N'', N'', N'', 2, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-02T14:20:18.000' AS DateTime))
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (103, 101, N'0,100,101', N'研发部门', 1, N'若依', N'15888888888', N'ry@qq.com', 1, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-01-25T16:33:32.000' AS DateTime))
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (104, 101, N'0,100,101', N'市场部门', 2, N'若依', N'15888888888', N'ry@qq.com', 1, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (105, 101, N'0,100,101', N'测试部门', 3, N'若依', N'15888888888', N'ry@qq.com', 1, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (106, 101, N'0,100,101', N'财务部门', 4, N'若依', N'15888888888', N'ry@qq.com', 1, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (107, 101, N'0,100,101', N'运维部门', 5, N'若依', N'15888888888', N'ry@qq.com', 1, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (108, 102, N'0,100,102', N'市场部门', 1, N'若依', N'15888888888', N'ry@qq.com', 2, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (109, 102, N'0,100,102', N'财务部门', 2, N'若依', N'15888888888', N'ry@qq.com', 2, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (200, 100, N'0,100', N'XXC有限公司', 10, NULL, NULL, NULL, 3, N'0', N'2', N'admin', CAST(N'2024-03-16T11:57:11.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (201, 200, N'0,100,200', N'市场部', 10, NULL, NULL, NULL, 3, N'0', N'2', N'admin', CAST(N'2024-03-16T11:57:33.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (202, 100, N'0,100', N'集团秘书处', 10, NULL, NULL, NULL, 5, N'0', N'2', N'admin', CAST(N'2024-03-19T15:04:34.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (203, 202, N'0,100,202', N'集团采购', 10, NULL, NULL, NULL, 5, N'0', N'2', N'admin', CAST(N'2024-03-19T15:04:55.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (204, 202, N'0,100,202', N'集团法务', 10, NULL, NULL, NULL, 5, N'0', N'2', N'admin', CAST(N'2024-03-19T15:05:28.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (205, 100, N'0,100', N'集团IT', 10, NULL, NULL, NULL, 5, N'0', N'2', N'admin', CAST(N'2024-03-19T15:05:41.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (206, 101, N'0,100,101', N'生产部', 10, NULL, NULL, NULL, 1, N'0', N'2', N'admin', CAST(N'2024-03-19T22:13:39.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (207, 206, N'0,100,101,206', N'印刷课', 10, NULL, NULL, NULL, 1, N'0', N'2', N'admin', CAST(N'2024-03-19T22:14:06.000' AS DateTime), N'', NULL)
INSERT [dbo].[sys_dept] ([dept_id], [parent_id], [ancestors], [dept_name], [order_num], [leader], [phone], [email], [company_id], [status], [del_flag], [create_by], [create_time], [update_by], [update_time]) VALUES (208, 206, N'0,100,101,206', N'模切课', 10, NULL, NULL, NULL, 1, N'0', N'2', N'admin', CAST(N'2024-03-19T22:45:25.000' AS DateTime), N'', NULL)
SET IDENTITY_INSERT [dbo].[sys_dept] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_dict_data] ON 

INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, 10, N'男', N'0', N'sys_user_sex', N'', N'', N'Y', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-21T15:18:24.947' AS DateTime), N'性别男')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, 2, N'女', N'1', N'sys_user_sex', N'', N'', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'性别女')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (3, 3, N'未知', N'2', N'sys_user_sex', N'', N'', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'性别未知')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (4, 1, N'显示', N'0', N'sys_show_hide', N'', N'primary', N'Y', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'显示菜单')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (5, 2, N'隐藏', N'1', N'sys_show_hide', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'隐藏菜单')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (6, 1, N'正常', N'0', N'sys_normal_disable', N'', N'primary', N'Y', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'正常状态')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (7, 2, N'停用', N'1', N'sys_normal_disable', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'停用状态')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (8, 1, N'正常', N'0', N'sys_job_status', N'', N'primary', N'Y', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'正常状态')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (9, 2, N'暂停', N'1', N'sys_job_status', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'停用状态')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (10, 1, N'默认', N'DEFAULT', N'sys_job_group', N'', N'', N'Y', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'默认分组')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (11, 2, N'系统', N'SYSTEM', N'sys_job_group', N'', N'', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'系统分组')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (12, 1, N'是', N'Y', N'sys_yes_no', N'', N'primary', N'Y', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2023-09-28T08:41:46.000' AS DateTime), N'系统默认是')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (13, 2, N'否', N'N', N'sys_yes_no', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2023-09-28T08:41:50.000' AS DateTime), N'系统默认否')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (14, 1, N'通知', N'1', N'sys_notice_type', N'', N'warning', N'Y', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'通知')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (15, 2, N'公告', N'2', N'sys_notice_type', N'', N'success', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'公告')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (16, 1, N'正常', N'0', N'sys_notice_status', N'', N'primary', N'Y', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'正常状态')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (17, 2, N'关闭', N'1', N'sys_notice_status', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'关闭状态')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (18, 99, N'其他', N'0', N'sys_oper_type', N'', N'info', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'其他操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (19, 1, N'新增', N'1', N'sys_oper_type', N'', N'info', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'新增操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (20, 2, N'修改', N'2', N'sys_oper_type', N'', N'info', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'修改操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (21, 3, N'删除', N'3', N'sys_oper_type', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'删除操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (22, 4, N'授权', N'4', N'sys_oper_type', N'', N'primary', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'授权操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (23, 5, N'导出', N'5', N'sys_oper_type', N'', N'warning', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'导出操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (24, 6, N'导入', N'6', N'sys_oper_type', N'', N'warning', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'导入操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (25, 7, N'强退', N'7', N'sys_oper_type', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'强退操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (26, 8, N'生成代码', N'8', N'sys_oper_type', N'', N'warning', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'生成操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (27, 9, N'清空数据', N'9', N'sys_oper_type', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'清空操作')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (28, 1, N'成功', N'0', N'sys_common_status', N'', N'primary', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'正常状态')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (29, 2, N'失败', N'1', N'sys_common_status', N'', N'danger', N'N', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'停用状态')
INSERT [dbo].[sys_dict_data] ([dict_code], [dict_sort], [dict_label], [dict_value], [dict_type], [css_class], [list_class], [is_default], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (153, 0, N'采购订单', N'PO', N'pur_bill_type', NULL, N'default', N'N', N'0', N'admin', CAST(N'2023-10-17T10:35:31.000' AS DateTime), N'', NULL, NULL)
SET IDENTITY_INSERT [dbo].[sys_dict_data] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_dict_type] ON 

INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, N'用户性别', N'sys_user_sex', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'用户性别列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, N'菜单状态', N'sys_show_hide', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'菜单状态列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (3, N'系统开关', N'sys_normal_disable', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'系统开关列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (4, N'任务状态', N'sys_job_status', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'任务状态列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (5, N'任务分组', N'sys_job_group', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'任务分组列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (6, N'系统是否', N'sys_yes_no', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'系统是否列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (7, N'通知类型', N'sys_notice_type', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'通知类型列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (8, N'通知状态', N'sys_notice_status', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'通知状态列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (9, N'操作类型', N'sys_oper_type', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'操作类型列表')
INSERT [dbo].[sys_dict_type] ([dict_id], [dict_name], [dict_type], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (10, N'系统状态', N'sys_common_status', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'登录状态列表')
SET IDENTITY_INSERT [dbo].[sys_dict_type] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_job] ON 

INSERT [dbo].[sys_job] ([job_id], [job_name], [job_group], [invoke_target], [cron_expression], [misfire_policy], [concurrent], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, N'系统默认（无参）', N'DEFAULT', N'ryTask.ryNoParams', N'0/10 * * * * ?', N'3', N'1', N'1', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-16T11:55:41.000' AS DateTime), N'')
INSERT [dbo].[sys_job] ([job_id], [job_name], [job_group], [invoke_target], [cron_expression], [misfire_policy], [concurrent], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, N'系统默认（有参）', N'DEFAULT', N'ryTask.ryParams(''ry'')', N'0/15 * * * * ?', N'3', N'1', N'1', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_job] ([job_id], [job_name], [job_group], [invoke_target], [cron_expression], [misfire_policy], [concurrent], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (3, N'系统默认（多参）', N'DEFAULT', N'ryTask.ryMultipleParams(''ry'', true, 2000L, 316.50D, 100)', N'0/20 * * * * ?', N'3', N'1', N'1', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
SET IDENTITY_INSERT [dbo].[sys_job] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_logininfor] ON 

INSERT [dbo].[sys_logininfor] ([info_id], [user_name], [ipaddr], [login_location], [browser], [os], [status], [msg], [login_time]) VALUES (1, N'admin', N'127.0.0.1', N'内网IP', N'Chrome 12', N'Windows 10', N'0', N'登录成功', CAST(N'2024-03-23T08:54:20.200' AS DateTime))
SET IDENTITY_INSERT [dbo].[sys_logininfor] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_menu] ON 

INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, N'系统管理', 0, 10, N'system', NULL, N'', 1, 0, N'M', N'0', N'0', N'', N'system', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-02-29T09:21:13.000' AS DateTime), N'系统管理目录')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, N'系统监控', 0, 999, N'monitor', NULL, N'', 1, 0, N'M', N'0', N'0', N'', N'monitor', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-23T09:09:15.543' AS DateTime), N'系统监控目录')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (3, N'系统工具', 0, 900, N'tool', NULL, N'', 1, 0, N'M', N'0', N'0', N'', N'tool', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-23T09:09:01.610' AS DateTime), N'系统工具目录')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (100, N'用户管理', 1, 1, N'user', N'system/user/index', N'', 1, 0, N'C', N'0', N'0', N'system:user:list', N'user', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'用户管理菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (101, N'角色管理', 1, 2, N'role', N'system/role/index', N'', 1, 0, N'C', N'0', N'0', N'system:role:list', N'peoples', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'角色管理菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (102, N'菜单管理', 1, 3, N'menu', N'system/menu/index', N'', 1, 0, N'C', N'0', N'0', N'system:menu:list', N'tree-table', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'菜单管理菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (103, N'部门管理', 1, 4, N'dept', N'system/dept/index', N'', 1, 0, N'C', N'0', N'0', N'system:dept:list', N'tree', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'部门管理菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (104, N'岗位管理', 1, 6, N'post', N'system/post/index', N'', 1, 0, N'C', N'0', N'0', N'system:post:list', N'post', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-01-17T16:45:17.000' AS DateTime), N'岗位管理菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (105, N'字典管理', 1, 7, N'dict', N'system/dict/index', N'', 1, 0, N'C', N'0', N'0', N'system:dict:list', N'dict', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-01-17T16:45:36.000' AS DateTime), N'字典管理菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (106, N'参数设置', 1, 8, N'config', N'system/config/index', N'', 1, 0, N'C', N'0', N'0', N'system:config:list', N'edit', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-01-17T16:46:02.000' AS DateTime), N'参数设置菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (107, N'通知公告', 1, 9, N'notice', N'system/notice/index', N'', 1, 0, N'C', N'0', N'0', N'system:notice:list', N'message', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-01-17T16:45:53.000' AS DateTime), N'通知公告菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (108, N'日志管理', 1, 10, N'log', N'', N'', 1, 0, N'M', N'0', N'0', N'', N'log', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-01-17T16:45:47.000' AS DateTime), N'日志管理菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (109, N'在线用户', 2, 1, N'online', N'monitor/online/index', N'', 1, 0, N'C', N'0', N'0', N'monitor:online:list', N'online', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'在线用户菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (110, N'定时任务', 2, 2, N'job', N'monitor/job/index', N'', 1, 0, N'C', N'0', N'0', N'monitor:job:list', N'job', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'定时任务菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (111, N'数据监控', 2, 3, N'druid', N'monitor/druid/index', N'', 1, 0, N'C', N'0', N'0', N'monitor:druid:list', N'druid', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'数据监控菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (112, N'服务监控', 2, 4, N'server', N'monitor/server/index', N'', 1, 0, N'C', N'0', N'0', N'monitor:server:list', N'server', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'服务监控菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (113, N'缓存监控', 2, 5, N'cache', N'monitor/cache/index', N'', 1, 0, N'C', N'0', N'0', N'monitor:cache:list', N'redis', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'缓存监控菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (114, N'缓存列表', 2, 6, N'cacheList', N'monitor/cache/list', N'', 1, 0, N'C', N'0', N'0', N'monitor:cache:list', N'redis-list', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'缓存列表菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (115, N'表单构建', 3, 1, N'build', N'tool/build/index', N'', 1, 0, N'C', N'0', N'0', N'tool:build:list', N'build', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'表单构建菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (116, N'代码生成', 3, 2, N'gen', N'tool/gen/index', N'', 1, 0, N'C', N'0', N'0', N'tool:gen:list', N'code', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'代码生成菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (117, N'系统接口', 3, 3, N'swagger', N'tool/swagger/index', N'', 1, 0, N'C', N'0', N'0', N'tool:swagger:list', N'swagger', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'系统接口菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (500, N'操作日志', 108, 1, N'operlog', N'monitor/operlog/index', N'', 1, 0, N'C', N'0', N'0', N'monitor:operlog:list', N'form', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'操作日志菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (501, N'登录日志', 108, 2, N'logininfor', N'monitor/logininfor/index', N'', 1, 0, N'C', N'0', N'0', N'monitor:logininfor:list', N'logininfor', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'登录日志菜单')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1000, N'用户查询', 100, 1, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:user:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1001, N'用户新增', 100, 2, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:user:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1002, N'用户修改', 100, 3, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:user:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1003, N'用户删除', 100, 4, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:user:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1004, N'用户导出', 100, 5, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:user:export', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1005, N'用户导入', 100, 6, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:user:import', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1006, N'重置密码', 100, 7, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:user:resetPwd', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1007, N'角色查询', 101, 1, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:role:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1008, N'角色新增', 101, 2, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:role:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1009, N'角色修改', 101, 3, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:role:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1010, N'角色删除', 101, 4, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:role:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1011, N'角色导出', 101, 5, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:role:export', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1012, N'菜单查询', 102, 1, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:menu:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1013, N'菜单新增', 102, 2, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:menu:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1014, N'菜单修改', 102, 3, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:menu:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1015, N'菜单删除', 102, 4, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:menu:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1016, N'部门查询', 103, 1, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dept:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1017, N'部门新增', 103, 2, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dept:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1018, N'部门修改', 103, 3, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dept:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1019, N'部门删除', 103, 4, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dept:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1020, N'岗位查询', 104, 1, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:post:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1021, N'岗位新增', 104, 2, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:post:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1022, N'岗位修改', 104, 3, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:post:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1023, N'岗位删除', 104, 4, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:post:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1024, N'岗位导出', 104, 5, N'', N'', N'', 1, 0, N'F', N'0', N'0', N'system:post:export', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1025, N'字典查询', 105, 1, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dict:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1026, N'字典新增', 105, 2, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dict:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1027, N'字典修改', 105, 3, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dict:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1028, N'字典删除', 105, 4, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dict:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1029, N'字典导出', 105, 5, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:dict:export', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1030, N'参数查询', 106, 1, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:config:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1031, N'参数新增', 106, 2, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:config:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1032, N'参数修改', 106, 3, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:config:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1033, N'参数删除', 106, 4, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:config:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1034, N'参数导出', 106, 5, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:config:export', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1035, N'公告查询', 107, 1, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:notice:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1036, N'公告新增', 107, 2, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:notice:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1037, N'公告修改', 107, 3, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:notice:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1038, N'公告删除', 107, 4, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'system:notice:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1039, N'操作查询', 500, 1, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:operlog:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1040, N'操作删除', 500, 2, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:operlog:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1041, N'日志导出', 500, 3, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:operlog:export', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1042, N'登录查询', 501, 1, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:logininfor:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1043, N'登录删除', 501, 2, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:logininfor:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1044, N'日志导出', 501, 3, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:logininfor:export', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1045, N'账户解锁', 501, 4, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:logininfor:unlock', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1046, N'在线查询', 109, 1, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:online:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1047, N'批量强退', 109, 2, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:online:batchLogout', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1048, N'单条强退', 109, 3, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:online:forceLogout', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1049, N'任务查询', 110, 1, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:job:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1050, N'任务新增', 110, 2, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:job:add', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1051, N'任务修改', 110, 3, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:job:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1052, N'任务删除', 110, 4, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:job:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1053, N'状态修改', 110, 5, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:job:changeStatus', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1054, N'任务导出', 110, 6, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'monitor:job:export', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1055, N'生成查询', 116, 1, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'tool:gen:query', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1056, N'生成修改', 116, 2, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'tool:gen:edit', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1057, N'生成删除', 116, 3, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'tool:gen:remove', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1058, N'导入代码', 116, 4, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'tool:gen:import', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1059, N'预览代码', 116, 5, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'tool:gen:preview', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1060, N'生成代码', 116, 6, N'#', N'', N'', 1, 0, N'F', N'0', N'0', N'tool:gen:code', N'#', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_menu] ([menu_id], [menu_name], [parent_id], [order_num], [path], [component], [query], [is_frame], [is_cache], [menu_type], [visible], [status], [perms], [icon], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2174, N'修改密码', 100, 8, N'', NULL, NULL, 1, 0, N'F', N'0', N'0', N'system:user:updatePwd', N'#', N'admin', CAST(N'2022-04-29T11:27:13.000' AS DateTime), N'', NULL, N'')
SET IDENTITY_INSERT [dbo].[sys_menu] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_notice] ON 

INSERT [dbo].[sys_notice] ([notice_id], [notice_title], [notice_type], [notice_content], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, N'温馨提醒：2018-07-01 若依新版本发布啦', N'2', 0xE696B0E78988E69CACE58685E5AEB9, N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'管理员')
INSERT [dbo].[sys_notice] ([notice_id], [notice_title], [notice_type], [notice_content], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, N'维护通知：2018-07-01 若依系统凌晨维护', N'1', 0xE7BBB4E68AA4E58685E5AEB9, N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'管理员')
SET IDENTITY_INSERT [dbo].[sys_notice] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_oper_log] ON 

INSERT [dbo].[sys_oper_log] ([oper_id], [title], [business_type], [method], [request_method], [operator_type], [oper_name], [dept_name], [oper_url], [oper_ip], [oper_location], [oper_param], [json_result], [status], [error_msg], [oper_time], [cost_time]) VALUES (1, N'操作日志', 9, N'com.ruoyi.web.controller.monitor.SysOperlogController.clean()', N'DELETE', 1, N'admin', N'研发部门', N'/monitor/operlog/clean', N'127.0.0.1', N'内网IP', N'{}', N'{"msg":"操作成功","code":200}', 0, NULL, CAST(N'2024-03-23T09:19:21.127' AS DateTime), 4)
INSERT [dbo].[sys_oper_log] ([oper_id], [title], [business_type], [method], [request_method], [operator_type], [oper_name], [dept_name], [oper_url], [oper_ip], [oper_location], [oper_param], [json_result], [status], [error_msg], [oper_time], [cost_time]) VALUES (2, N'代码生成', 3, N'com.ruoyi.generator.controller.GenController.remove()', N'DELETE', 1, N'admin', N'研发部门', N'/tool/gen/2', N'127.0.0.1', N'内网IP', N'{}', N'{"msg":"操作成功","code":200}', 0, NULL, CAST(N'2024-03-23T09:23:03.737' AS DateTime), 11)
INSERT [dbo].[sys_oper_log] ([oper_id], [title], [business_type], [method], [request_method], [operator_type], [oper_name], [dept_name], [oper_url], [oper_ip], [oper_location], [oper_param], [json_result], [status], [error_msg], [oper_time], [cost_time]) VALUES (3, N'代码生成', 6, N'com.ruoyi.generator.controller.GenController.importTableSave()', N'POST', 1, N'admin', N'研发部门', N'/tool/gen/importTable', N'127.0.0.1', N'内网IP', N'{"tables":"sys_user"}', N'{"msg":"操作成功","code":200}', 0, NULL, CAST(N'2024-03-23T09:24:12.413' AS DateTime), 246)
INSERT [dbo].[sys_oper_log] ([oper_id], [title], [business_type], [method], [request_method], [operator_type], [oper_name], [dept_name], [oper_url], [oper_ip], [oper_location], [oper_param], [json_result], [status], [error_msg], [oper_time], [cost_time]) VALUES (4, N'代码生成', 2, N'com.ruoyi.generator.controller.GenController.editSave()', N'PUT', 1, N'admin', N'研发部门', N'/tool/gen', N'127.0.0.1', N'内网IP', N'{"businessName":"user","className":"SysUser","columns":[{"capJavaField":"UserId","columnComment":"用户ID","columnId":9,"columnName":"user_id","columnType":"bigint","createBy":"admin","createTime":"2024-03-23 09:24:12","edit":false,"htmlType":"input","increment":true,"insert":true,"isIncrement":"1","isInsert":"1","isPk":"1","isRequired":"1","javaField":"userId","javaType":"Long","list":false,"params":{},"pk":true,"query":false,"queryType":"EQ","required":true,"sort":1,"superColumn":false,"tableId":3,"usableColumn":false},{"capJavaField":"DeptId","columnComment":"部门ID","columnId":10,"columnName":"dept_id","columnType":"bigint","createBy":"admin","createTime":"2024-03-23 09:24:12","edit":true,"htmlType":"input","increment":false,"insert":true,"isEdit":"1","isIncrement":"0","isInsert":"1","isList":"1","isPk":"0","isQuery":"1","isRequired":"0","javaField":"deptId","javaType":"Long","list":true,"params":{},"pk":false,"query":true,"queryType":"EQ","required":false,"sort":2,"superColumn":false,"tableId":3,"usableColumn":false},{"capJavaField":"UserName","columnComment":"用户账号","columnId":11,"columnName":"user_name","columnType":"nvarchar","createBy":"admin","createTime":"2024-03-23 09:24:12","edit":true,"htmlType":"input","increment":false,"insert":true,"isEdit":"1","isIncrement":"0","isInsert":"1","isList":"1","isPk":"0","isQuery":"1","isRequired":"1","javaField":"userName","javaType":"String","list":true,"params":{},"pk":false,"query":true,"queryType":"LIKE","required":true,"sort":3,"superColumn":false,"tableId":3,"usableColumn":false},{"capJavaField":"NickName","columnComment":"用户昵称","columnId":12,"columnName":"nick_name","columnType":"nvarchar","createBy":"admin","createTime":"2024-03-23 09:24:12","edit":true,"htmlType":"input","increment":false,"insert":true,"isEdit":"1","isIncrement":"0","isInsert":"1","isList":"1","isPk":"0","isQuery":"1","isRequired":"1","javaField":"nickName","javaType":"String","list":true,"params":{},"pk":false,"query":true,"queryType":"LIKE","requi', N'{"msg":"操作成功","code":200}', 0, NULL, CAST(N'2024-03-23T09:24:54.600' AS DateTime), 82)
SET IDENTITY_INSERT [dbo].[sys_oper_log] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_post] ON 

INSERT [dbo].[sys_post] ([post_id], [post_code], [post_name], [post_sort], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, N'ceo', N'董事长', 1, N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_post] ([post_id], [post_code], [post_name], [post_sort], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, N'se', N'项目经理', 2, N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_post] ([post_id], [post_code], [post_name], [post_sort], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (3, N'hr', N'人力资源', 3, N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
INSERT [dbo].[sys_post] ([post_id], [post_code], [post_name], [post_sort], [status], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (4, N'user', N'普通员工', 4, N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'')
SET IDENTITY_INSERT [dbo].[sys_post] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_role] ON 

INSERT [dbo].[sys_role] ([role_id], [role_name], [role_key], [role_sort], [data_scope], [menu_check_strictly], [dept_check_strictly], [status], [del_flag], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, N'超级管理员', N'admin', 1, N'1', 1, 1, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', NULL, N'超级管理员')
INSERT [dbo].[sys_role] ([role_id], [role_name], [role_key], [role_sort], [data_scope], [menu_check_strictly], [dept_check_strictly], [status], [del_flag], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, N'普通角色', N'common', 10, N'2', 1, 1, N'0', N'0', N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-23T09:07:25.593' AS DateTime), N'普通角色')
INSERT [dbo].[sys_role] ([role_id], [role_name], [role_key], [role_sort], [data_scope], [menu_check_strictly], [dept_check_strictly], [status], [del_flag], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (100, N'测试', N'test', 2, N'2', 1, 1, N'0', N'2', N'admin', CAST(N'2024-03-12T16:40:33.000' AS DateTime), N'admin', CAST(N'2024-03-23T08:55:21.573' AS DateTime), NULL)
INSERT [dbo].[sys_role] ([role_id], [role_name], [role_key], [role_sort], [data_scope], [menu_check_strictly], [dept_check_strictly], [status], [del_flag], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (101, N'aaa', N'test1', 0, N'1', 1, 1, N'0', N'2', N'admin', CAST(N'2024-03-21T21:52:06.000' AS DateTime), N'', NULL, NULL)
SET IDENTITY_INSERT [dbo].[sys_role] OFF
GO
SET IDENTITY_INSERT [dbo].[sys_user] ON 

INSERT [dbo].[sys_user] ([user_id], [dept_id], [user_name], [nick_name], [user_type], [email], [phonenumber], [sex], [avatar], [password], [status], [del_flag], [login_ip], [login_date], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (1, 103, N'admin', N'若依', N'00', N'ry@163.com', N'15888888888', N'1', N'', N'$2a$10$7JB720yubVSZvUI0rEqK/.VqGOZTH.ulu33dHOiBE8ByOhJIrdAu2', N'0', N'0', N'127.0.0.1', CAST(N'2024-03-23T08:54:20.170' AS DateTime), N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'', CAST(N'2024-03-23T08:54:20.197' AS DateTime), N'管理员')
INSERT [dbo].[sys_user] ([user_id], [dept_id], [user_name], [nick_name], [user_type], [email], [phonenumber], [sex], [avatar], [password], [status], [del_flag], [login_ip], [login_date], [create_by], [create_time], [update_by], [update_time], [remark]) VALUES (2, 103, N'ry', N'若依', N'00', N'ry@qq.com', N'15666666666', N'1', N'/profile/avatar/2024/03/12/blob_20240312164631A001.png', N'$2a$10$ypGq7qcGgPHvsP0LBJL7L.6TMFWsnyblJ.5SxR3TGDuC4vobefQIm', N'0', N'0', N'127.0.0.1', CAST(N'2024-03-22T10:50:37.097' AS DateTime), N'admin', CAST(N'2023-09-23T14:13:07.000' AS DateTime), N'admin', CAST(N'2024-03-23T09:19:10.850' AS DateTime), N'测试员')
SET IDENTITY_INSERT [dbo].[sys_user] OFF
GO
INSERT [dbo].[sys_user_post] ([user_id], [post_id]) VALUES (1, 1)
INSERT [dbo].[sys_user_post] ([user_id], [post_id]) VALUES (1, 2)
INSERT [dbo].[sys_user_post] ([user_id], [post_id]) VALUES (2, 2)
GO
INSERT [dbo].[sys_user_role] ([user_id], [role_id]) VALUES (1, 1)
INSERT [dbo].[sys_user_role] ([user_id], [role_id]) VALUES (1, 2)
INSERT [dbo].[sys_user_role] ([user_id], [role_id]) VALUES (2, 2)
GO
/****** Object:  Index [idx_sys_oper_log_bt]    Script Date: 2024-03-23 09:52:19 ******/
CREATE NONCLUSTERED INDEX [idx_sys_oper_log_bt] ON [dbo].[sys_oper_log]
(
	[business_type] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
/****** Object:  Index [idx_sys_oper_log_ot]    Script Date: 2024-03-23 09:52:19 ******/
CREATE NONCLUSTERED INDEX [idx_sys_oper_log_ot] ON [dbo].[sys_oper_log]
(
	[oper_time] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
/****** Object:  Index [idx_sys_oper_log_s]    Script Date: 2024-03-23 09:52:19 ******/
CREATE NONCLUSTERED INDEX [idx_sys_oper_log_s] ON [dbo].[sys_oper_log]
(
	[status] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
GO
ALTER TABLE [dbo].[sys_config] ADD  DEFAULT ('') FOR [config_name]
GO
ALTER TABLE [dbo].[sys_config] ADD  DEFAULT ('') FOR [config_key]
GO
ALTER TABLE [dbo].[sys_config] ADD  DEFAULT ('') FOR [config_value]
GO
ALTER TABLE [dbo].[sys_config] ADD  DEFAULT ('N') FOR [config_type]
GO
ALTER TABLE [dbo].[sys_config] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_config] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_config] ADD  DEFAULT (NULL) FOR [remark]
GO
ALTER TABLE [dbo].[sys_dept] ADD  CONSTRAINT [DF__sys_dept__parent__50FB042B]  DEFAULT ((0)) FOR [parent_id]
GO
ALTER TABLE [dbo].[sys_dept] ADD  CONSTRAINT [DF__sys_dept__ancest__51EF2864]  DEFAULT ('') FOR [ancestors]
GO
ALTER TABLE [dbo].[sys_dept] ADD  CONSTRAINT [DF__sys_dept__dept_n__52E34C9D]  DEFAULT ('') FOR [dept_name]
GO
ALTER TABLE [dbo].[sys_dept] ADD  CONSTRAINT [DF__sys_dept__order___53D770D6]  DEFAULT ((0)) FOR [order_num]
GO
ALTER TABLE [dbo].[sys_dept] ADD  CONSTRAINT [DF__sys_dept__status__54CB950F]  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_dept] ADD  CONSTRAINT [DF__sys_dept__del_fl__55BFB948]  DEFAULT ('0') FOR [del_flag]
GO
ALTER TABLE [dbo].[sys_dept] ADD  CONSTRAINT [DF__sys_dept__create__56B3DD81]  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_dept] ADD  CONSTRAINT [DF__sys_dept__update__57A801BA]  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_dict_data] ADD  DEFAULT ((0)) FOR [dict_sort]
GO
ALTER TABLE [dbo].[sys_dict_data] ADD  DEFAULT ('') FOR [dict_label]
GO
ALTER TABLE [dbo].[sys_dict_data] ADD  DEFAULT ('') FOR [dict_value]
GO
ALTER TABLE [dbo].[sys_dict_data] ADD  DEFAULT ('') FOR [dict_type]
GO
ALTER TABLE [dbo].[sys_dict_data] ADD  DEFAULT ('N') FOR [is_default]
GO
ALTER TABLE [dbo].[sys_dict_data] ADD  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_dict_data] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_dict_data] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_dict_type] ADD  DEFAULT ('') FOR [dict_name]
GO
ALTER TABLE [dbo].[sys_dict_type] ADD  DEFAULT ('') FOR [dict_type]
GO
ALTER TABLE [dbo].[sys_dict_type] ADD  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_dict_type] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_dict_type] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_job] ADD  DEFAULT ('') FOR [job_name]
GO
ALTER TABLE [dbo].[sys_job] ADD  DEFAULT ('DEFAULT') FOR [job_group]
GO
ALTER TABLE [dbo].[sys_job] ADD  DEFAULT ('') FOR [cron_expression]
GO
ALTER TABLE [dbo].[sys_job] ADD  DEFAULT ('3') FOR [misfire_policy]
GO
ALTER TABLE [dbo].[sys_job] ADD  DEFAULT ('1') FOR [concurrent]
GO
ALTER TABLE [dbo].[sys_job] ADD  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_job] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_job] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_job_log] ADD  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_job_log] ADD  DEFAULT ('') FOR [exception_info]
GO
ALTER TABLE [dbo].[sys_logininfor] ADD  DEFAULT ('') FOR [user_name]
GO
ALTER TABLE [dbo].[sys_logininfor] ADD  DEFAULT ('') FOR [ipaddr]
GO
ALTER TABLE [dbo].[sys_logininfor] ADD  DEFAULT ('') FOR [login_location]
GO
ALTER TABLE [dbo].[sys_logininfor] ADD  DEFAULT ('') FOR [browser]
GO
ALTER TABLE [dbo].[sys_logininfor] ADD  DEFAULT ('') FOR [os]
GO
ALTER TABLE [dbo].[sys_logininfor] ADD  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_logininfor] ADD  DEFAULT ('') FOR [msg]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ((0)) FOR [parent_id]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ((0)) FOR [order_num]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ('') FOR [path]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ((1)) FOR [is_frame]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ((0)) FOR [is_cache]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ('') FOR [menu_type]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ('0') FOR [visible]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ('#') FOR [icon]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_menu] ADD  DEFAULT ('') FOR [remark]
GO
ALTER TABLE [dbo].[sys_notice] ADD  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_notice] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_notice] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [title]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ((0)) FOR [business_type]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [method]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [request_method]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ((0)) FOR [operator_type]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [oper_name]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [dept_name]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [oper_url]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [oper_ip]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [oper_location]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [oper_param]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [json_result]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ((0)) FOR [status]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ('') FOR [error_msg]
GO
ALTER TABLE [dbo].[sys_oper_log] ADD  DEFAULT ((0)) FOR [cost_time]
GO
ALTER TABLE [dbo].[sys_post] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_post] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_role] ADD  DEFAULT ('1') FOR [data_scope]
GO
ALTER TABLE [dbo].[sys_role] ADD  DEFAULT ((1)) FOR [menu_check_strictly]
GO
ALTER TABLE [dbo].[sys_role] ADD  DEFAULT ((1)) FOR [dept_check_strictly]
GO
ALTER TABLE [dbo].[sys_role] ADD  DEFAULT ('0') FOR [del_flag]
GO
ALTER TABLE [dbo].[sys_role] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_role] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('00') FOR [user_type]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('') FOR [email]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('') FOR [phonenumber]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('0') FOR [sex]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('') FOR [avatar]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('') FOR [password]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('0') FOR [status]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('0') FOR [del_flag]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('') FOR [login_ip]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('') FOR [create_by]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT ('') FOR [update_by]
GO
ALTER TABLE [dbo].[sys_user] ADD  DEFAULT (NULL) FOR [remark]
GO
ALTER TABLE [dbo].[qrtz_blob_triggers]  WITH CHECK ADD  CONSTRAINT [FK_qrtz_blob_triggers] FOREIGN KEY([sched_name], [trigger_name], [trigger_group])
REFERENCES [dbo].[qrtz_triggers] ([sched_name], [trigger_name], [trigger_group])
GO
ALTER TABLE [dbo].[qrtz_blob_triggers] CHECK CONSTRAINT [FK_qrtz_blob_triggers]
GO
ALTER TABLE [dbo].[qrtz_cron_triggers]  WITH CHECK ADD  CONSTRAINT [FK_qrtz_cron_triggers] FOREIGN KEY([sched_name], [trigger_name], [trigger_group])
REFERENCES [dbo].[qrtz_triggers] ([sched_name], [trigger_name], [trigger_group])
GO
ALTER TABLE [dbo].[qrtz_cron_triggers] CHECK CONSTRAINT [FK_qrtz_cron_triggers]
GO
ALTER TABLE [dbo].[qrtz_simple_triggers]  WITH CHECK ADD  CONSTRAINT [FK_qrtz_simple_triggers] FOREIGN KEY([sched_name], [trigger_name], [trigger_group])
REFERENCES [dbo].[qrtz_triggers] ([sched_name], [trigger_name], [trigger_group])
GO
ALTER TABLE [dbo].[qrtz_simple_triggers] CHECK CONSTRAINT [FK_qrtz_simple_triggers]
GO
ALTER TABLE [dbo].[qrtz_simprop_triggers]  WITH CHECK ADD  CONSTRAINT [FK_qrtz_simprop_triggers] FOREIGN KEY([sched_name], [trigger_name], [trigger_group])
REFERENCES [dbo].[qrtz_triggers] ([sched_name], [trigger_name], [trigger_group])
GO
ALTER TABLE [dbo].[qrtz_simprop_triggers] CHECK CONSTRAINT [FK_qrtz_simprop_triggers]
GO
ALTER TABLE [dbo].[qrtz_triggers]  WITH CHECK ADD  CONSTRAINT [FK_qrtz_triggers] FOREIGN KEY([sched_name], [job_name], [job_group])
REFERENCES [dbo].[qrtz_job_details] ([sched_name], [job_name], [job_group])
GO
ALTER TABLE [dbo].[qrtz_triggers] CHECK CONSTRAINT [FK_qrtz_triggers]
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'编号' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'table_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'表名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'table_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'表描述' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'table_comment'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'关联子表的表名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'sub_table_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'子表关联的外键名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'sub_table_fk_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'实体类名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'class_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'使用的模板（crud单表操作 tree树表操作）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'tpl_category'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'生成包路径' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'package_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'生成模块名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'module_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'生成业务名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'business_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'生成功能名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'function_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'生成功能作者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'function_author'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'生成代码方式（0zip压缩包 1自定义路径）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'gen_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'生成路径（不填默认项目路径）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'gen_path'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'其它生成选项' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'options'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'代码生成业务表' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'编号' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'column_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'归属表编号' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'table_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'列名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'column_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'列描述' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'column_comment'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'列类型' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'column_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'JAVA类型' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'java_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'JAVA字段名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'java_field'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否主键（1是）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'is_pk'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否自增（1是）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'is_increment'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否必填（1是）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'is_required'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否为插入字段（1是）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'is_insert'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否编辑字段（1是）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'is_edit'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否列表字段（1是）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'is_list'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否查询字段（1是）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'is_query'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'查询方式（等于、不等于、大于、小于、范围）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'query_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'显示类型（文本框、文本域、下拉框、复选框、单选框、日期控件）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'html_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典类型' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'dict_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'排序' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'sort'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'代码生成业务表字段' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'gen_table_column'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_blob_triggers', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_name的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_blob_triggers', @level2type=N'COLUMN',@level2name=N'trigger_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_group的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_blob_triggers', @level2type=N'COLUMN',@level2name=N'trigger_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'存放持久化Trigger对象' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_blob_triggers', @level2type=N'COLUMN',@level2name=N'blob_data'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_calendars', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'日历名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_calendars', @level2type=N'COLUMN',@level2name=N'calendar_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'存放持久化calendar对象' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_calendars', @level2type=N'COLUMN',@level2name=N'calendar'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_cron_triggers', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_name的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_cron_triggers', @level2type=N'COLUMN',@level2name=N'trigger_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_group的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_cron_triggers', @level2type=N'COLUMN',@level2name=N'trigger_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'cron表达式' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_cron_triggers', @level2type=N'COLUMN',@level2name=N'cron_expression'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'时区' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_cron_triggers', @level2type=N'COLUMN',@level2name=N'time_zone_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度器实例id' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'entry_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_name的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'trigger_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_group的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'trigger_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度器实例名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'instance_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'触发的时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'fired_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'定时器制定的时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'sched_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'优先级' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'priority'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'状态' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'state'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'job_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务组名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'job_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否并发' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'is_nonconcurrent'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否接受恢复执行' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_fired_triggers', @level2type=N'COLUMN',@level2name=N'requests_recovery'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'job_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务组名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'job_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'相关介绍' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'description'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'执行任务类名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'job_class_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否持久化' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'is_durable'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否并发' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'is_nonconcurrent'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否更新数据' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'is_update_data'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否接受恢复执行' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'requests_recovery'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'存放持久化job对象' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_job_details', @level2type=N'COLUMN',@level2name=N'job_data'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_locks', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'悲观锁名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_locks', @level2type=N'COLUMN',@level2name=N'lock_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_paused_trigger_grps', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_group的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_paused_trigger_grps', @level2type=N'COLUMN',@level2name=N'trigger_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_scheduler_state', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'实例名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_scheduler_state', @level2type=N'COLUMN',@level2name=N'instance_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'上次检查时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_scheduler_state', @level2type=N'COLUMN',@level2name=N'last_checkin_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'检查间隔时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_scheduler_state', @level2type=N'COLUMN',@level2name=N'checkin_interval'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simple_triggers', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_name的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simple_triggers', @level2type=N'COLUMN',@level2name=N'trigger_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_group的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simple_triggers', @level2type=N'COLUMN',@level2name=N'trigger_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'重复的次数统计' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simple_triggers', @level2type=N'COLUMN',@level2name=N'repeat_count'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'重复的间隔时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simple_triggers', @level2type=N'COLUMN',@level2name=N'repeat_interval'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'已经触发的次数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simple_triggers', @level2type=N'COLUMN',@level2name=N'times_triggered'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_name的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'trigger_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_triggers表trigger_group的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'trigger_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'String类型的trigger的第一个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'str_prop_1'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'String类型的trigger的第二个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'str_prop_2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'String类型的trigger的第三个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'str_prop_3'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'int类型的trigger的第一个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'int_prop_1'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'int类型的trigger的第二个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'int_prop_2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'long类型的trigger的第一个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'long_prop_1'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'long类型的trigger的第二个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'long_prop_2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'decimal类型的trigger的第一个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'dec_prop_1'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'decimal类型的trigger的第二个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'dec_prop_2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Boolean类型的trigger的第一个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'bool_prop_1'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'Boolean类型的trigger的第二个参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_simprop_triggers', @level2type=N'COLUMN',@level2name=N'bool_prop_2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调度名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'sched_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'触发器的名字' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'trigger_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'触发器所属组的名字' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'trigger_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_job_details表job_name的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'job_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'qrtz_job_details表job_group的外键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'job_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'相关介绍' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'description'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'上一次触发时间（毫秒）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'next_fire_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'下一次触发时间（默认为-1表示不触发）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'prev_fire_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'优先级' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'priority'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'触发器状态' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'trigger_state'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'触发器的类型' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'trigger_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'开始时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'start_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'结束时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'end_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'日程表名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'calendar_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'补偿执行的策略' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'misfire_instr'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'存放持久化job对象' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'qrtz_triggers', @level2type=N'COLUMN',@level2name=N'job_data'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'参数主键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'config_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'参数名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'config_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'参数键名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'config_key'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'参数键值' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'config_value'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'系统内置（Y是 N否）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'config_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_config', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'部门id' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'dept_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'父部门id' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'parent_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'祖级列表' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'ancestors'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'部门名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'dept_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'显示顺序' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'order_num'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'负责人' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'leader'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'联系电话' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'phone'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'邮箱' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'email'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'公司别' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'company_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'部门状态（0正常 1停用）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'删除标志（0代表存在 2代表删除）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'del_flag'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dept', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典编码' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'dict_code'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典排序' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'dict_sort'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典标签' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'dict_label'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典键值' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'dict_value'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典类型' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'dict_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'样式属性（其他样式扩展）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'css_class'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'表格回显样式' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'list_class'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否默认（Y是 N否）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'is_default'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'状态（0正常 1停用）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_data', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典主键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'dict_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'dict_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'字典类型' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'dict_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'状态（0正常 1停用）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_dict_type', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'job_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'job_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务组名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'job_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调用目标字符串' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'invoke_target'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'cron执行表达式' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'cron_expression'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'计划执行错误策略（1立即执行 2执行一次 3放弃执行）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'misfire_policy'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否并发执行（0允许 1禁止）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'concurrent'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'状态（0正常 1暂停）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注信息' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务日志ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job_log', @level2type=N'COLUMN',@level2name=N'job_log_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job_log', @level2type=N'COLUMN',@level2name=N'job_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'任务组名' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job_log', @level2type=N'COLUMN',@level2name=N'job_group'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'调用目标字符串' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job_log', @level2type=N'COLUMN',@level2name=N'invoke_target'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'日志信息' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job_log', @level2type=N'COLUMN',@level2name=N'job_message'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'执行状态（0正常 1失败）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job_log', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'异常信息' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job_log', @level2type=N'COLUMN',@level2name=N'exception_info'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_job_log', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'访问ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'info_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户账号' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'user_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'登录IP地址' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'ipaddr'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'登录地点' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'login_location'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'浏览器类型' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'browser'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'操作系统' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'os'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'登录状态（0成功 1失败）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'提示消息' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'msg'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'访问时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_logininfor', @level2type=N'COLUMN',@level2name=N'login_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'菜单ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'menu_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'菜单名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'menu_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'父菜单ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'parent_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'显示顺序' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'order_num'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'路由地址' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'path'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'组件路径' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'component'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'路由参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'query'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否为外链（0是 1否）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'is_frame'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'是否缓存（0缓存 1不缓存）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'is_cache'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'菜单类型（M目录 C菜单 F按钮）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'menu_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'菜单状态（0显示 1隐藏）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'visible'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'菜单状态（0正常 1停用）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'权限标识' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'perms'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'菜单图标' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'icon'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_menu', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'公告ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'notice_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'公告标题' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'notice_title'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'公告类型（1通知 2公告）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'notice_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'公告内容' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'notice_content'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'公告状态（0正常 1关闭）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_notice', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'日志主键' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'oper_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'模块标题' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'title'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'业务类型（0其它 1新增 2修改 3删除）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'business_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'方法名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'method'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'请求方式' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'request_method'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'操作类别（0其它 1后台用户 2手机端用户）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'operator_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'操作人员' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'oper_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'部门名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'dept_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'请求URL' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'oper_url'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'主机地址' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'oper_ip'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'操作地点' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'oper_location'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'请求参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'oper_param'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'返回参数' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'json_result'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'操作状态（0正常 1异常）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'错误消息' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'error_msg'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'操作时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'oper_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'消耗时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_oper_log', @level2type=N'COLUMN',@level2name=N'cost_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'岗位ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'post_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'岗位编码' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'post_code'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'岗位名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'post_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'显示顺序' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'post_sort'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'状态（0正常 1停用）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'职位表' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_post'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'角色ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'role_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'角色名称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'role_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'角色权限字符串' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'role_key'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'显示顺序' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'role_sort'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'数据范围（1：全部数据权限 2：自定数据权限 3：本部门数据权限 4：本部门及以下数据权限）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'data_scope'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'菜单树选择项是否关联显示' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'menu_check_strictly'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'部门树选择项是否关联显示' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'dept_check_strictly'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'角色状态（0正常 1停用）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'删除标志（0代表存在 2代表删除）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'del_flag'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'角色表' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'角色ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role_dept', @level2type=N'COLUMN',@level2name=N'role_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'部门ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role_dept', @level2type=N'COLUMN',@level2name=N'dept_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'角色ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role_menu', @level2type=N'COLUMN',@level2name=N'role_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'菜单ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_role_menu', @level2type=N'COLUMN',@level2name=N'menu_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'user_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'部门ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'dept_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户账号' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'user_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户昵称' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'nick_name'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户类型（00系统用户）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'user_type'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户邮箱' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'email'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'手机号码' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'phonenumber'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户性别（0男 1女 2未知）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'sex'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'头像地址' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'avatar'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'密码' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'password'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'帐号状态（0正常 1停用）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'删除标志（0代表存在 2代表删除）' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'del_flag'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'最后登录IP' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'login_ip'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'最后登录时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'login_date'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'create_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'创建时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'create_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新者' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'update_by'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'更新时间' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'update_time'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'备注' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user', @level2type=N'COLUMN',@level2name=N'remark'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户表' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user_post', @level2type=N'COLUMN',@level2name=N'user_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'岗位ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user_post', @level2type=N'COLUMN',@level2name=N'post_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'用户ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user_role', @level2type=N'COLUMN',@level2name=N'user_id'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_Description', @value=N'角色ID' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'TABLE',@level1name=N'sys_user_role', @level2type=N'COLUMN',@level2name=N'role_id'
GO
USE [master]
GO
ALTER DATABASE [ruoyi] SET  READ_WRITE 
GO
