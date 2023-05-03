title 'Docker Custom Configuration'

TRUSTED_USER = attribute('trusted_user')
MANAGEABLE_CONTAINER_NUMBER = attribute('managable_container_number')
BENCHMARK_VERSION = attribute('benchmark_version')
CONTAINER_CAPADD = attribute('container_capadd')

# check if docker exists
only_if('docker not found') do
  command('docker').exist?
end

control 'self-define 1' do
  title 'docker-runc CVE-2019-5736'
  desc 'Through specific container image or exec operation, an attacker can obtain the file handle of runc execution of the host and modify the binary file of runc, so as to obtain the root execution permission of the host.'
  impact 1.0

  tag cis:'Docker: self-define 1'
  tag level:1

  describe docker do
    its('version.Client.Version') { should cmp > '18.09.2' }
    its('version.Server.Version') { should cmp > '18.09.2' }
  end
  runc_version = command('runc -v | grep -o "\w*\.\w*\.\w*-rc\w*"').stdout
  runc_compare = Gem::Version.new('1.0.0-rc6') < Gem::Version.new(runc_version) || runc_version == ""
  describe runc_compare do
    it { should eq true }
  end
end

control 'self-define 2' do
  title 'docker-cp CVE-2019-14271'
  desc 'This vulnerability can be exploited if the container has been compromised by a previous attack process (e.g. through other vulnerabilities and information disclosure, etc.), or when a user runs a malicious container image from an untrusted source (e.g. registry, etc.). If the user then executes the vulnerable CP command to copy files from the infected container, the attacker can escape and take full control of the host and all other containers in it.'
  impact 1.0

  tag cis:'Docker: self-define 2'
  tag level:1

  describe docker do
    its('version.Client.Version') { should_not cmp == '19.03.0' }
    its('version.Server.Version') { should_not cmp == '19.03.0' }
  end
end

control 'self-define 3' do
  title 'containerd-shim CVE-2020-15257'
  desc 'When containerd operates runc, it will create a corresponding process and generate an abstract socket through which docker controls and communicates with the container. The socket can be found in the /proc/net/unix file of the host. When the network of the host is shared within the Docker container, the docker container can be controlled by loading the socket to cause escape.'
  impact 1.0

  tag cis:'Docker: self-define 3'
  tag level:1

  docker.containers.running?.ids.each do |id|
    describe command("docker exec #{id} cat /proc/net/unix | grep /containerd-shim/").stdout do
      it { should be_empty }
    end
  end
end

control 'self-define 4' do
  title 'dirtycow CVE-2016-5195'
  desc 'In Linux, there is a function: VDSO (virtual dvdynamic shared object), which is a small shared library that can automatically map the kernel to the address space of all user programs.The Dirty Cow vulnerability is used to write Payload to some idle memory in VDSO and change the execution order of the function so that the Shellcode can be called before executing the normal function. Since docker shares the kernel with the host, modifying vdso directly affects the host kernel.'
  impact 1.0

  tag cis:'Docker: self-define 4'
  tag level:1

  only_if { os.linux? }
  kernel_version = command('uname -r | grep -o "\w*\.\w*\.\w*"').stdout
  kernel_compare = Gem::Version.new('2.6.22') <= Gem::Version.new(kernel_version)
  only_if { kernel_compare }
  kernel_cmp = Gem::Version.new('4.8.3') > Gem::Version.new(kernel_version)
  describe kernel_cmp do
    it { should eq false }
  end
end

control 'self-define 5' do
  title 'CAP_SYS_MODULE'
  desc 'If the container is given a CAP_SYS_MODULE, the container will be able to insert the kernel module into the kernel of the host. If a kernel module that generates a rebound shell is written and loaded, the attacker can obtain the root user\'s shell and realize container escape.'
  impact 1.0

  tag cis:'Docker: self-define 5'
  tag level:1

  describe command("docker ps | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}'| grep SYS_MODUL").stdout do
    it {should be_empty}
  end
end

control 'self-define 6' do
  title 'CAP_DAC_READ_SEARCH'
  desc 'If the container is given DAC_READ_SEARCH capability, an attacker will be able to open a file pointed to by an arbitrary handle inside the container. In a 64 bit system, the length of the file handle is 8 bytes, of which the first 4 bytes are the inode number. According to this principle, an attacker can traverse the inode inside the container, find the target file, and then brutally crack the file handle. After 4 bytes, he can find the handle to the file, and finally open the file successfully.'
  impact 1.0

  tag cis:'Docker: self-define 6'
  tag level:1

  describe command("docker ps | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}'| grep DAC_READ_SEARCH").stdout do
    it {should be_empty}
  end
end

control 'self-define 7' do
  title 'CAP_SYS_ADMIN'
  desc 'CAP_ SYSAdmin escape needs to disable docker\'s default AppArmor configuration file or AppArmor allows mount syscall to run. When the container is started with the --cap-add = SYSADMIN flag, the container process is allowed to execute a series of system management commands such as mount and umount, causing the container to escape.'
  impact 1.0

  tag cis:'Docker: self-define 7'
  tag level:1

  describe command("docker ps | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}'| grep SYS_ADMIN").stdout do
    it {should be_empty}
  end
end

control 'self-define 8' do
  title 'CAP_SYS_PTRACE'
  desc 'Abuse of CAP_SYS_PTRACE to obtain root privileges, upgrade to root user and retrieve flags.'
  impact 1.0

  tag cis:'Docker: self-define 8'
  tag level:1

  describe command("docker ps | xargs docker inspect --format '{{ .Id }}: CapAdd={{ .HostConfig.CapAdd }} CapDrop={{ .HostConfig.CapDrop }}'| grep SYS_PTRACE").stdout do
    it {should be_empty}
  end
end

control 'self-define 9' do
title 'Procfs Escaping'
desc 'procfs is a pseudo file system, which dynamically reflects the state of processes and other components in the system, including many sensitive and important files. Therefore, it is also very dangerous to mount the procfs of the host to an uncontrolled container, especially when the root permission is enabled by default in the container and the User Namespace is not opened. /proc/sys/kernel/core_pattern in procfs is responsible for configuring the export mode of memory dump data when the process crashes.'
impact 1.0

  tag cis:'Docker: self-define 9'
  tag level:1

  docker.containers.running?.ids.each do |id|
    describe command("docker inspect -f {{.Mounts}} #{id} | grep 'bind  /proc'").stdout do
      it { should be_empty }
    end
  end
end

control 'self-define 10' do
title 'docker.sock Escaping'
desc 'If docker.sock is mounted inside the container, the container user is root and has the right to read and write docker.sock. Therefore, you can further escape by accessing the docker API through docker.sock, creating a privileged container and connecting it.'
impact 1.0

  tag cis:'Docker: self-define 10'
  tag level:1

  docker.containers.running?.ids.each do |id|
    describe command("docker inspect -f {{.Mounts}} #{id} | grep docker.sock").stdout do
      it { should be_empty}
    end
  end
end

