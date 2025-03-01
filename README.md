# Web Reconnaissance Tool

Terminal tabanlı bir web keşif aracı. Bu araç, verilen bir web sitesinin alt alan adlarını (subdomains) tarar ve açık portları tespit eder.

## Özellikler

- Alt alan adı (subdomain) keşfi
- Port taraması
- Servis ve versiyon tespiti
- Çoklu iş parçacığı desteği (multithreading)
- Sonuçları dosyaya kaydetme

## Gereksinimler

- Python 3.6+
- nmap
- Aşağıdaki Python paketleri:
  - dnspython
  - requests
  - python-nmap
  - tqdm

## Kurulum

1. Gereksinimleri yükleyin:

```bash
pip install -r requirements.txt
```

2. Kali Linux'ta nmap yüklü değilse:

```bash
apt-get install nmap
```

## Kali Linux'a Kurulum

Aşağıdaki adımları takip ederek aracı Kali Linux'a kurabilirsiniz:

1. Öncelikle, projeyi bilgisayarınıza indirin:

```bash
git clone https://github.com/ernerk/WebRecon.git
cd WebRecon
```

2. Gerekli paketleri yükleyin:

```bash
pip3 install -r requirements.txt
```

3. nmap'in yüklü olduğundan emin olun:

```bash
sudo apt-get update && sudo apt-get install -y nmap
```

4. Çalıştırma izinlerini ayarlayın:

```bash
chmod +x run.sh
```

5. Aracı çalıştırın:

```bash
./run.sh -t example.com
```

Alternatif olarak, aracı doğrudan Python ile de çalıştırabilirsiniz:

```bash
python3 web_recon.py -t example.com
```

## Kullanım

```bash
python web_recon.py -t example.com
```

### Parametreler

- `-t, --target`: Hedef URL veya alan adı (zorunlu)
- `-o, --output`: Sonuçları kaydetmek için dosya adı (isteğe bağlı)
- `-p, --ports`: Taranacak portlar (virgülle ayrılmış, varsayılan: 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080)
- `-j, --threads`: Tarama için iş parçacığı sayısı (varsayılan: 10)

### Örnekler

Basit bir tarama:
```bash
python web_recon.py -t example.com
```

Sonuçları dosyaya kaydetme:
```bash
python web_recon.py -t example.com -o sonuclar.txt
```

Belirli portları tarama:
```bash
python web_recon.py -t example.com -p 80,443,8080
```

İş parçacığı sayısını artırma:
```bash
python web_recon.py -t example.com -j 20
```

## Güvenlik Notu

Bu aracı yalnızca izin verilen sistemlerde kullanın. İzinsiz tarama yapmak yasal sorunlara neden olabilir.
