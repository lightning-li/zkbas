package transaction

import (
	"github.com/bnb-chain/zkbnb/service/apiserver/internal/response"
	zkbnbtypes "github.com/bnb-chain/zkbnb/types"
	"net/http"

	"github.com/zeromicro/go-zero/rest/httpx"

	"github.com/bnb-chain/zkbnb/service/apiserver/internal/logic/transaction"
	"github.com/bnb-chain/zkbnb/service/apiserver/internal/svc"
	"github.com/bnb-chain/zkbnb/service/apiserver/internal/types"
)

func GetPendingTxsHandler(svcCtx *svc.ServiceContext) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.ReqGetRange
		if err := httpx.Parse(r, &req); err != nil {
			bizErr := zkbnbtypes.AppErrInvalidParam.RefineError(err)
			response.Handle(w, nil, bizErr)
			return
		}

		l := transaction.NewGetPendingTxsLogic(r.Context(), svcCtx)
		resp, err := l.GetPendingTxs(&req)
		response.Handle(w, resp, err)
	}
}
