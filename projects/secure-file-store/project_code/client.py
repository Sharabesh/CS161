"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
from util import to_json_string, from_json_string

import pdb

BLOCK_SIZE = 1024

class Client(BaseClient):

    class MerkleNode:
        def __init__(self, loc, hash, left, right, iv = None, data = None):
            self.loc = loc
            self.hash = hash
            self.left = left
            self.right = right
            self.iv = iv
            self.data = data

    def create_merkle(self, value):
        blocks = [value[i:i+BLOCK_SIZE] for i in range(0, len(value), BLOCK_SIZE)]

        nodes = []  
        for block in blocks:
            loc = self.crypto.get_random_bytes(32)
            hash = self.crypto.cryptographic_hash(block, 'SHA256')
            iv = self.crypto.get_random_bytes(16)
            nodes.append(self.MerkleNode(loc, hash, None, None, iv, block))

        while len(nodes) > 1:
            new_nodes = []
            if len(nodes) % 2 == 1:
                nodes.append(None)

            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i+1]
                loc = self.crypto.get_random_bytes(32)

                if right:
                    hash = self.crypto.cryptographic_hash(left.hash + right.hash, 'SHA256')
                else:
                    hash = self.crypto.cryptographic_hash(left.hash, 'SHA256')

                new_nodes.append(self.MerkleNode(loc, hash, left, right))

            nodes = new_nodes

        return nodes[0]

    # Function TO BE COMPLETED!!!
    def upload_merkle(self, node, enc_key, mac_key, root = True):
        node_value = {
            'hash': node.hash,
            'left': node.left.loc if node.left else None,
            'right': node.right.loc if node.right else None,
            'iv': None,
            'data': None
        }

        if node.data:
            node_value['iv'] = node.iv
            node_value['data'] = self.sym_enc(node.data, node.iv, enc_key)


        value = to_json_string(node_value)

        if root:
            self.put_no_enc(value, node.loc, mac_key)
        else:
            self.storage_server.put(node.loc, value)

        if not node.data:
            if node.left:
                self.upload_merkle(node.left, enc_key, mac_key, False)
            if node.right:
                self.upload_merkle(node.right, enc_key, mac_key, False)


    def download_merkle(self, loc, enc_key, mac_key, root = True):
        server_node_val = self.storage_server.get(loc)
        if not server_node_val:
            raise IntegrityError

        try:
            server_node = from_json_string(server_node_val)

            if root:
                # check top hash validity
                node_pkg = server_node
                server_node = from_json_string(node_pkg['value'])
                if self.mac(loc + node_pkg['value'], mac_key) != node_pkg['mac']:
                    raise IntegrityError

            data = ''

            if server_node['data']:
                data += self.sym_dec(server_node['data'], server_node['iv'], enc_key)

            if server_node['left']:
                data += self.download_merkle(server_node['left'], enc_key, mac_key, False)

            if server_node['right']:
                data += self.download_merkle(server_node['right'], enc_key, mac_key, False)

            if root:
                return (data, server_node['hash'])
            else:
                return data
        except:
            raise IntegrityError

    def mac(self, message, mac_key):
        return self.crypto.message_authentication_code(message, mac_key, hash_name = 'SHA256')

    def verify_mac(self, message, mac_key, mac_val):
        new_mac_val = self.crypto.message_authentication_code(message, mac_key, hash_name = 'SHA256')
        return mac_val == new_mac_val

    def sym_enc(self, message, iv, sym_key):
        return self.crypto.symmetric_encrypt(message, sym_key, cipher_name = 'AES', mode_name = 'CBC', IV = iv)

    def sym_dec(self, message, iv, sym_key):
        return self.crypto.symmetric_decrypt(message, sym_key, cipher_name = 'AES', mode_name = 'CBC', IV = iv)

    # new instance variables
    dir_loc = None
    dir_keys_loc = None
    dir_enc_key = None
    dir_mac_key = None
    dir = None
    cache = {}

    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        self.init_dir_keys()
        self.init_dir()

    def init_dir_keys(self):
        self.dir_keys_loc = self.username + '/dir_keys'
        value = self.storage_server.get(self.dir_keys_loc)

        if not value:
            # key not already on the server
            self.dir_enc_key = self.crypto.get_random_bytes(32)
            self.dir_mac_key = self.crypto.get_random_bytes(32)

            dir_keys = {
                'dir_enc_key' : self.dir_enc_key,
                'dir_mac_key' : self.dir_mac_key
            }

            dir_keys_str = to_json_string(dir_keys)
            enc_value = self.crypto.asymmetric_encrypt(dir_keys_str, self.private_key)
            sig = self.crypto.asymmetric_sign(self.dir_keys_loc + enc_value, self.private_key)

            dir_keys_pkg = {
                'enc_value' : enc_value,
                'sig' : sig
            }

            value = to_json_string(dir_keys_pkg)

            if not self.storage_server.put(self.dir_keys_loc, value):
                # unable to upload sym_key to storage server
                raise IntegrityError

        else:
            # keys fetched from server
            try:
                dir_keys_pkg = from_json_string(value)
                sig = dir_keys_pkg['sig']
                enc_value = dir_keys_pkg['enc_value']

                if not self.crypto.asymmetric_verify(self.dir_keys_loc + enc_value, sig, self.private_key):
                    raise IntegrityError

                dir_keys_str = self.crypto.asymmetric_decrypt(enc_value, self.private_key)
                dir_keys = from_json_string(dir_keys_str)
                self.dir_enc_key = dir_keys['dir_enc_key']
                self.dir_mac_key = dir_keys['dir_mac_key']

            except(ValueError, TypeError, KeyError, CryptoError):
                # malformed key package
                raise IntegrityError

    def init_dir(self):
        self.dir_loc = self.username + '/dir'
        if not self.get_dir():
            self.dir = {}
            self.upload_dir()

    def upload_dir(self):
        iv = self.crypto.get_random_bytes(16)
        dir_str = to_json_string(self.dir)
        enc_value = self.sym_enc(dir_str, iv, self.dir_enc_key)

        dir_pkg = {
            'iv': iv,
            'mac': self.mac(self.dir_loc + iv + enc_value, self.dir_mac_key),
            'enc_value': enc_value
        }

        value = to_json_string(dir_pkg)

        if not self.storage_server.put(self.dir_loc, value):
            # need to keep dir updated at all times
            raise IntegrityError

    def get_dir(self):
        value = self.storage_server.get(self.dir_loc)
        if not value:
            return False

        try:
            dir_pkg = from_json_string(value)

            iv = dir_pkg['iv']
            mac = dir_pkg['mac']
            enc_value = dir_pkg['enc_value']

            if not self.verify_mac(self.dir_loc + iv + enc_value, self.dir_mac_key, mac):
                raise IntegrityError

            dir_str = self.sym_dec(enc_value, iv, self.dir_enc_key)
            self.dir = from_json_string(dir_str)
            return True

        except(ValueError, TypeError, KeyError, CryptoError):
            raise IntegrityError

    def put(self, value, loc, enc_key, mac_key):
        iv = self.crypto.get_random_bytes(16)
        enc_value = self.sym_enc(value, iv, enc_key)

        pkg = {
            'iv': iv,
            'mac': self.mac(loc + iv + enc_value, mac_key),
            'enc_value': enc_value,
        }

        value = to_json_string(pkg)

        if not self.storage_server.put(loc, value):
            # already updated directory but can't upload file
            return False

        return True

    def put_no_enc(self, value, loc, mac_key):
        pkg = {
            'mac': self.mac(loc + value, mac_key),
            'value': value,
        }

        value = to_json_string(pkg)

        if not self.storage_server.put(loc, value):
            # already updated directory but can't upload file
            return False

        return True

    def get(self, loc, enc_key, mac_key):
        value = self.storage_server.get(loc)
        if not value:
            # we know we uploaded the file, and it was later deleted
            raise IntegrityError()

        try:
            pkg = from_json_string(value)

            iv = pkg['iv']
            mac = pkg['mac']
            enc_value = pkg['enc_value']

            if not self.verify_mac(loc + iv + enc_value, mac_key, mac):
                raise IntegrityError     

            value = self.sym_dec(enc_value, iv, enc_key)
            return value

        except(ValueError, TypeError, KeyError, CryptoError):
            raise IntegrityError

    def follow_gateways(self, loc, enc_key, mac_key):
        """
        returns a link to the actual file, as well as the keys used to access it.
        """
        value = self.storage_server.get(loc)
        if not value:
            # we know we uploaded the file, and it was later deleted
            raise IntegrityError()

        try:
            pkg = from_json_string(value)

            iv = pkg['iv']
            mac = pkg['mac']
            enc_value = pkg['enc_value']

            if not self.verify_mac(loc + iv  + enc_value, mac_key, mac):
                raise IntegrityError     

            value = self.sym_dec(enc_value, iv, enc_key)
            gateway_record = from_json_string(value)
            next_loc = gateway_record['loc']
            next_enc_key = gateway_record['enc_key']
            next_mac_key = gateway_record['mac_key']

            if gateway_record['is_leaf']:
                return {'loc': next_loc, 'mac_key': next_mac_key, 'enc_key': next_enc_key}
            else:
                return self.follow_gateways(next_loc, next_enc_key, next_mac_key)

        except(ValueError, TypeError, KeyError, CryptoError):
            raise IntegrityError

    def upload(self, name, value):
        self.get_dir()
        if not name in self.dir:
            # uploading a new file
            loc = self.crypto.get_random_bytes(32)
            enc_key = self.crypto.get_random_bytes(32)
            mac_key = self.crypto.get_random_bytes(32)

            file_record = {
                'loc': loc,
                'enc_key': enc_key,
                'mac_key': mac_key,
                'is_gateway': False,
                'shared': {}
            }

            self.dir[name] = file_record
            self.upload_dir()
            
            # upload actual file
            merkle = self.create_merkle(value)

            file_meta = {
                'length': len(value),
                'tree': merkle.loc,
            }

            self.upload_merkle(merkle, enc_key, mac_key)

            file_meta_value = to_json_string(file_meta)

            return self.put(file_meta_value, loc, enc_key, mac_key)

        else: 
            file_record = self.dir[name]
            enc_key = file_record['enc_key']
            mac_key = file_record['mac_key']
            meta_loc = file_record['loc']

            if file_record['is_gateway']:
                target = self.follow_gateways(file_record['loc'], enc_key, mac_key)
                enc_key = target['enc_key']
                mac_key = target['mac_key']
                meta_loc = target['loc']

                meta_val = self.get(meta_loc, enc_key, mac_key)
            else:
                meta_val = self.get(meta_loc, enc_key, mac_key)


            meta = from_json_string(meta_val)

            merkle = self.create_merkle(value)
            if meta['length'] != len(value):
                # different file lengths
                self.upload_merkle(merkle, enc_key, mac_key)
                meta = {
                    'length': len(value),
                    'tree': merkle.loc,
                }
                meta_val = to_json_string(meta)
                return self.put(meta_val, meta_loc, enc_key, mac_key)
            else:
                # same file lengths
                return self.efficient_update(merkle, meta['tree'], enc_key, mac_key)
                
                # self.put(value, target['loc'], target['enc_key'], target['mac_key'])

    def efficient_update(self, merkle, node_loc, enc_key, mac_key, root = True):
        server_node_val = self.storage_server.get(node_loc)
        if not server_node_val:
            raise IntegrityError

        try:
            server_node = from_json_string(server_node_val)
            if root:
                server_node = from_json_string(server_node['value'])

            if merkle.hash == server_node['hash']:
                return

            node = {
                'hash': merkle.hash,
                'left': server_node['left'],
                'right': server_node['right'],
                'iv': None,
                'data': None
            }

            if merkle.data:
                node['iv'] = merkle.iv
                node['data'] = self.sym_enc(merkle.data, merkle.iv, enc_key)

            node_value = to_json_string(node)

            if root:
                if not self.put_no_enc(node_value, node_loc, mac_key):
                    raise IntegrityError

            else:
                if not self.storage_server.put(node_loc, node_value):
                    raise IntegrityError

            if merkle.left:
                self.efficient_update(merkle.left, server_node['left'], enc_key, mac_key, False)

            if merkle.right:
                self.efficient_update(merkle.right, server_node['right'], enc_key, mac_key, False)
        except:
            raise IntegrityError

    def download(self, name):
        self.get_dir()
        if not name in self.dir:
            # file not part of user's dir
            return None

        file_record = self.dir[name]
        loc = file_record['loc']
        enc_key = file_record['enc_key']
        mac_key = file_record['mac_key']

        if file_record['is_gateway']:
            target = self.follow_gateways(file_record['loc'], file_record['enc_key'], file_record['mac_key'])
            enc_key = target['enc_key']
            mac_key = target['mac_key']
            meta_val = self.get(target['loc'], target['enc_key'], target['mac_key']) 
        else:
            meta_val = self.get(loc, enc_key, mac_key)

        if not meta_val:
            raise IntegrityError 

        meta = from_json_string(meta_val)
        value, root_hash = self.download_merkle(meta['tree'], enc_key, mac_key)
        merkle = self.create_merkle(value)
        if merkle.hash != root_hash:
            raise IntegrityError
        return value

    def share(self, user, name):
        self.get_dir()
        if not name in self.dir:
            # file not part of user's dir
            return None
        file_record = self.dir[name]

        target_pub_key = self.pks.get_public_key(user)
        if not target_pub_key:
            # can't find user to share with
            return None

        # generate new share record
        loc = self.crypto.get_random_bytes(32)
        enc_key = self.crypto.get_random_bytes(32)
        mac_key = self.crypto.get_random_bytes(32)

        share_record = {
            'loc': loc,
            'enc_key': enc_key,
            'mac_key': mac_key,
        }

        file_record['shared'][user] = share_record
        self.upload_dir()

        # create and upload a gateway file
        gateway_record = {
            'loc': file_record['loc'],
            'enc_key': file_record['enc_key'],
            'mac_key': file_record['mac_key'],
            'is_leaf': not file_record['is_gateway']
        }

        value = to_json_string(gateway_record)

        self.put(value, loc, enc_key, mac_key)

        # construct sharing message

        value = to_json_string(share_record)
        iv = self.crypto.get_random_bytes(16)
        enc_key = self.crypto.get_random_bytes(32)
        enc_value = self.sym_enc(value, iv, enc_key)
        enc_enc_key = self.crypto.asymmetric_encrypt(enc_key, target_pub_key)
        msg = {
            'enc_value': enc_value,
            'iv': iv,
            'enc_enc_key': enc_enc_key,
            'sig': self.crypto.asymmetric_sign(enc_enc_key + iv + enc_value, self.private_key)
        }

        return to_json_string(msg)

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        from_pub_key = self.pks.get_public_key(from_username)
        if not from_pub_key:
            return False

        try:
            msg = from_json_string(message)
            enc_value = msg['enc_value']
            enc_enc_key = msg['enc_enc_key']
            iv = msg['iv']
            sig = msg['sig']

            if not self.crypto.asymmetric_verify(enc_enc_key + iv + enc_value, sig, from_pub_key):
                raise IntegrityError

            enc_key = self.crypto.asymmetric_decrypt(enc_enc_key, self.private_key)
            value = self.sym_dec(enc_value, iv, enc_key)
            share_record = from_json_string(value)

            file_record = {
                'loc': share_record['loc'],
                'enc_key': share_record['enc_key'],
                'mac_key': share_record['mac_key'],
                'is_gateway': True,
                'shared': {}
            }

            self.get_dir()
            self.dir[newname] = file_record
            self.upload_dir()

        except(ValueError, TypeError, KeyError, CryptoError):
            raise IntegrityError

    def revoke(self, user, name):
        value = self.download(name)
        if not value:
            return False

        file_record = self.dir[name]
        shares = file_record['shared']

        # check to make sure we've shared with that user
        if not user in shares:
            return False
        else:
            shares.pop(user)

        # re-encrypt and upload the file again
        new_mac_key = self.crypto.get_random_bytes(32)
        new_enc_key = self.crypto.get_random_bytes(32)

        file_record['enc_key'] = new_enc_key
        file_record['mac_key'] = new_mac_key

        # upload actual file
        merkle = self.create_merkle(value)

        file_meta = {
            'length': len(value),
            'tree': merkle.loc,
        }

        self.upload_merkle(merkle, new_enc_key, new_mac_key)

        file_meta_value = to_json_string(file_meta)

        self.put(file_meta_value, file_record['loc'], new_enc_key, new_mac_key)

        self.upload_dir()
       
        for u in shares:
            share_record = shares[u]
            loc = share_record['loc']
            enc_key = share_record['enc_key']
            mac_key = share_record['mac_key']

            gateway_record = {
                'loc': file_record['loc'],
                'enc_key': new_enc_key,
                'mac_key': new_mac_key,
                'is_leaf': not file_record['is_gateway']
            }

            value = to_json_string(gateway_record)

            self.put(value, loc, enc_key, mac_key)

        return True



















