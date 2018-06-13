/****************************************************************************
* Copyright (C) 2017 by PolyLogyx, LLC                                      *
*                                                                           *
* This file implements a table called win_epp_table which basically queries *
* for end point security products on the system and displays their name,    *
* state, status etc. When run from a centralized console, it can be useful  *
* to get the collective EPP state of endpoints                              *
*                                                                           *
* The code is derived from the sample code at Microsoft that demonstrates   *
* the query code for the WMI classes WSC_SECURITY_PROVIDER_ANTIVIRUS,       *
* WSC_SECURITY_PROVIDER_ANTISPYWARE and WSC_SECURITY_PROVIDER_FIREWALL.     *
*
* The original code can be found at                                         *
* https://github.com/Microsoft/Windows-classic-samples/blob/master/Samples/WebSecurityCenter/cpp/WscApiSample.cpp
*                                                                           *
* To know more about osquery, visit https://osquery.io/                     *
****************************************************************************/

#include "stdafx.h"

#include <stdio.h>
#include <wscapi.h>
#include <iwscapi.h>

using namespace osquery;

#define WIN_EPP_TABLE "win_epp_table"

class PlgxWinEppTable : public TablePlugin {
private:
    TableColumns columns() const {
        return{
            std::make_tuple("product_type", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("product_name", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("product_state", TEXT_TYPE, ColumnOptions::DEFAULT),
            std::make_tuple("product_signatures", TEXT_TYPE, ColumnOptions::DEFAULT),
        };
    }

    HRESULT GetSecurityProducts(_In_ WSC_SECURITY_PROVIDER provider, QueryData& Results)
    {
        HRESULT                         hr = S_OK;
        IWscProduct*                    PtrProduct = nullptr;
        IWSCProductList*                PtrProductList = nullptr;
        BSTR                            PtrVal = nullptr;
        LONG                            ProductCount = 0;
        WSC_SECURITY_PRODUCT_STATE      ProductState;
        WSC_SECURITY_SIGNATURE_STATUS   ProductStatus;
        char ProdName[256] = { 0 };

        hr = CoCreateInstance(
            __uuidof(WSCProductList),
            NULL,
            CLSCTX_INPROC_SERVER,
            __uuidof(IWSCProductList),
            reinterpret_cast<LPVOID*> (&PtrProductList));
        if (FAILED(hr))
        {
            LOG(WARNING) << "CoCreateInstance returned error" << hr;
            goto exit;
        }

        hr = PtrProductList->Initialize(provider);
        if (FAILED(hr))
        {
            LOG(WARNING) << "Initialize failed with error" << hr;
            goto exit;
        }

        hr = PtrProductList->get_Count(&ProductCount);
        if (FAILED(hr))
        {
            LOG(WARNING) << "get_count failed with error" << hr;
            goto exit;
        }

        for (LONG i = 0; i < ProductCount; i++)
        {
            Row r;

            if (provider == WSC_SECURITY_PROVIDER_ANTIVIRUS)
            {
                r["product_type"] = "Anti-Virus";
            }
            else if (provider == WSC_SECURITY_PROVIDER_ANTISPYWARE)
            {
                r["product_type"] = "Anti-Spyware";
            }
            else if (provider == WSC_SECURITY_PROVIDER_FIREWALL)
            {
                r["product_type"] = "Firewall";
            }

            //
            // Get the next security product
            //
            hr = PtrProductList->get_Item(i, &PtrProduct);
            if (FAILED(hr))
            {
                LOG(WARNING) << "get_Item failed with error" << hr;
                goto exit;
            }

            //
            // Get the product name
            //
            hr = PtrProduct->get_ProductName(&PtrVal);
            if (FAILED(hr))
            {
                LOG(WARNING) << "get_ProductName failed with error" << hr;
                goto exit;
            }

            sprintf_s(ProdName, 256, "%ws", PtrVal);
            r["product_name"] = ProdName;

            // Caller is responsible for freeing the string
            SysFreeString(PtrVal);
            PtrVal = nullptr;

            //
            // Get the product state
            //
            hr = PtrProduct->get_ProductState(&ProductState);
            if (FAILED(hr))
            {
                LOG(WARNING) << "get_ProductState failed with error" << hr;
                goto exit;
            }

            if (ProductState == WSC_SECURITY_PRODUCT_STATE_ON)
            {
                r["product_state"] = "On";
            }
            else if (ProductState == WSC_SECURITY_PRODUCT_STATE_OFF)
            {
                r["product_state"] = "Off";
            }
            else if (ProductState == WSC_SECURITY_PRODUCT_STATE_SNOOZED)
            {
                r["product_state"] = "Snoozed";
            }
            else
            {
                r["product_state"] = "Expired";
            }

            //
            // Get the signature status (not applicable to firewall products)
            //
            if (provider != WSC_SECURITY_PROVIDER_FIREWALL)
            {
                hr = PtrProduct->get_SignatureStatus(&ProductStatus);
                if (FAILED(hr))
                {
                    LOG(WARNING) << "get_SignatureStatus failed with error" << hr;
                    goto exit;
                }

                if (ProductStatus == WSC_SECURITY_PRODUCT_UP_TO_DATE)
                    r["product_signatures"] = "Up-to-date";
                else
                    r["product_signatures"] = "Out-of-date";
            }
            else
            {
                r["product_signatures"] = "Not Applicable";
            }

            PtrProduct->Release();
            PtrProduct = nullptr;
            Results.push_back(r);
        }

    exit:

        if (nullptr != PtrVal)
        {
            SysFreeString(PtrVal);
        }
        if (nullptr != PtrProductList)
        {
            PtrProductList->Release();
        }
        if (nullptr != PtrProduct)
        {
            PtrProduct->Release();
        }
        return hr;
    }

    QueryData generate(QueryContext& request) {
        QueryData results;
        int     ret = 0;
        HRESULT hr = S_OK;
        int     iProviderCount = 0;
        WSC_SECURITY_PROVIDER providers[] = {
            WSC_SECURITY_PROVIDER_ANTIVIRUS,
            WSC_SECURITY_PROVIDER_ANTISPYWARE,
            WSC_SECURITY_PROVIDER_FIREWALL };

        CoInitializeEx(0, COINIT_APARTMENTTHREADED);

        iProviderCount = sizeof(providers) / sizeof(providers[0]);

        for (int i = 0; i < iProviderCount; i++)
        {
            //
            // Query security products of the specified type (AV, AS, or FW)
            //
            hr = GetSecurityProducts(providers[i], results);
            if (FAILED(hr))
            {
                break;
            }
        }

        return results;
    }
};

REGISTER_EXTERNAL(PlgxWinEppTable, "table", WIN_EPP_TABLE);
