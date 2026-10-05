package trojango

import (
	"io"
	"net"
	"sync"
	"testing"
	"trojan-panel-core/model/dto"

	"github.com/p4gefau1t/trojan-go/api/service"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type contractServer struct {
	service.UnimplementedTrojanServerServiceServer
	mu    sync.Mutex
	users map[string]*service.UserStatus
}

func (s *contractServer) ListUsers(_ *service.ListUsersRequest, stream service.TrojanServerService_ListUsersServer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.users {
		if err := stream.Send(&service.ListUsersResponse{Status: user}); err != nil {
			return err
		}
	}
	return nil
}

func (s *contractServer) GetUsers(stream service.TrojanServerService_GetUsersServer) error {
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		user := s.users[request.GetUser().GetHash()]
		if user != nil {
			user = proto.Clone(user).(*service.UserStatus)
		}
		s.mu.Unlock()
		if err := stream.Send(&service.GetUsersResponse{Success: user != nil, Status: user}); err != nil {
			return err
		}
	}
}

func (s *contractServer) SetUsers(stream service.TrojanServerService_SetUsersServer) error {
	for {
		request, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		s.mu.Lock()
		hash := request.GetStatus().GetUser().GetHash()
		switch request.Operation {
		case service.SetUsersRequest_Add:
			s.users[hash] = proto.Clone(request.Status).(*service.UserStatus)
		case service.SetUsersRequest_Delete:
			delete(s.users, hash)
		case service.SetUsersRequest_Modify:
			user := s.users[hash]
			if request.Status.TrafficTotal != nil {
				user.TrafficTotal = request.Status.TrafficTotal
			}
			if request.Status.SpeedLimit != nil {
				user.SpeedLimit = request.Status.SpeedLimit
			}
			user.IpLimit = request.Status.IpLimit
		}
		s.mu.Unlock()
		if err := stream.Send(&service.SetUsersResponse{Success: true}); err != nil {
			return err
		}
	}
}

func testTrojanAccountLifecycle(t *testing.T, api *trojanGoApi) {
	t.Helper()
	account := dto.TrojanGoAddUserDto{Hash: "4e47fcd9375f9385c7df6df8ad3e195b663f3e7c30294d6f48028d33", UploadTraffic: 123, DownloadTraffic: 456, IpLimit: 3, UploadSpeedLimit: 1024, DownloadSpeedLimit: 2048}
	if err := api.AddUser(account); err != nil {
		t.Fatal(err)
	}
	if err := api.AddUser(account); err != nil {
		t.Fatal(err)
	}
	users, err := api.ListUsers()
	if err != nil || len(users) != 1 {
		t.Fatalf("account add/list failed: %v %v", users, err)
	}
	user, err := api.GetUser(account.Hash)
	if err != nil || user == nil || user.GetTrafficTotal().GetUploadTraffic() != 123 || user.GetTrafficTotal().GetDownloadTraffic() != 456 || user.GetIpLimit() != 3 || user.GetSpeedLimit().GetUploadSpeed() != 1024 {
		t.Fatalf("account settings were lost: %v %v", user, err)
	}
	if err := api.SetUserSpeedLimit(account.Hash, 4096, 8192); err != nil {
		t.Fatal(err)
	}
	user, err = api.GetUser(account.Hash)
	if err != nil || user.GetSpeedLimit().GetUploadSpeed() != 4096 || user.GetSpeedLimit().GetDownloadSpeed() != 8192 {
		t.Fatal("speed update failed")
	}
	if err := api.SetUserIpLimit(account.Hash, 4); err != nil {
		t.Fatal(err)
	}
	user, err = api.GetUser(account.Hash)
	if err != nil || user.GetIpLimit() != 4 {
		t.Fatal("IP limit update failed")
	}
	if err := api.ReSetUserTrafficByHash(account.Hash); err != nil {
		t.Fatal(err)
	}
	user, err = api.GetUser(account.Hash)
	if err != nil || user.GetTrafficTotal().GetUploadTraffic() != 0 || user.GetTrafficTotal().GetDownloadTraffic() != 0 {
		t.Fatal("traffic reset failed")
	}
	if err := api.DeleteUser(account.Hash); err != nil {
		t.Fatal(err)
	}
	if err := api.DeleteUser(account.Hash); err != nil {
		t.Fatal(err)
	}
	users, err = api.ListUsers()
	if err != nil || len(users) != 0 {
		t.Fatal("account was not removed")
	}
}

func TestTrojanGoGRPCContract(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	service.RegisterTrojanServerServiceServer(server, &contractServer{users: make(map[string]*service.UserStatus)})
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	testTrojanAccountLifecycle(t, NewTrojanGoApi(uint(listener.Addr().(*net.TCPAddr).Port)))
}
