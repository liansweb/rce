def main():
    """
    生成requirements.txt文件
    """
    import subprocess
    import pkg_resources
    
    try:
        # 使用pip list获取已安装的包
        result = subprocess.run(['pip3', 'list', '--format=freeze'], capture_output=True, text=True, check=True)
        installed_packages = result.stdout.strip().split('\n')
        
        # 过滤掉不在当前项目中使用的包
        project_packages = []
        for package in installed_packages:
            package_name = package.split('==')[0]
            try:
                pkg_resources.get_distribution(package_name)
                project_packages.append(package)
            except pkg_resources.DistributionNotFound:
                pass
        
        # 写入requirements.txt文件
        with open('requirements.txt', 'w') as f:
            f.write('\n'.join(project_packages))
        
        print("成功生成requirements.txt文件")
    except subprocess.CalledProcessError as e:
        print(f"执行pip list命令失败: {e}")
    except IOError as e:
        print(f"写入requirements.txt文件失败: {e}")
    except Exception as e:
        print(f"生成requirements.txt文件时发生未知错误: {e}")
        
main()