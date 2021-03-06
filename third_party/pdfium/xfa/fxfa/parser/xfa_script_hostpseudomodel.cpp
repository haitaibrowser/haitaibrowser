// Copyright 2014 PDFium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Original code copyright 2014 Foxit Software Inc. http://www.foxitsoftware.com

#include "xfa/fxfa/parser/xfa_script_hostpseudomodel.h"

#include "xfa/fxfa/app/xfa_ffnotify.h"
#include "xfa/fxfa/fm2js/xfa_fm2jsapi.h"
#include "xfa/fxfa/parser/xfa_doclayout.h"
#include "xfa/fxfa/parser/xfa_document.h"
#include "xfa/fxfa/parser/xfa_document_layout_imp.h"
#include "xfa/fxfa/parser/xfa_localemgr.h"
#include "xfa/fxfa/parser/xfa_object.h"
#include "xfa/fxfa/parser/xfa_parser.h"
#include "xfa/fxfa/parser/xfa_parser_imp.h"
#include "xfa/fxfa/parser/xfa_script.h"
#include "xfa/fxfa/parser/xfa_script_imp.h"
#include "xfa/fxfa/parser/xfa_utils.h"
#include "xfa/fxjse/cfxjse_arguments.h"

CScript_HostPseudoModel::CScript_HostPseudoModel(CXFA_Document* pDocument)
    : CXFA_OrdinaryObject(pDocument, XFA_ELEMENT_HostPseudoModel) {
  m_uScriptHash = XFA_HASHCODE_Host;
}
CScript_HostPseudoModel::~CScript_HostPseudoModel() {}
void CScript_HostPseudoModel::Script_HostPseudoModel_LoadString(
    FXJSE_HVALUE hValue,
    CXFA_FFNotify* pNotify,
    uint32_t dwFlag) {
  CFX_WideString wsValue;
  pNotify->GetAppProvider()->LoadString(dwFlag, wsValue);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsValue).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_AppType(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_INVAlID_PROP_SET);
    return;
  }
  CFX_WideString wsAppType;
  pNotify->GetAppProvider()->GetAppType(wsAppType);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsAppType).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_FoxitAppType(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_INVAlID_PROP_SET);
    return;
  }
  CFX_WideString wsAppType;
  pNotify->GetAppProvider()->GetFoxitAppType(wsAppType);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsAppType).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_CalculationsEnabled(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  if (bSetting) {
    pNotify->GetDocProvider()->SetCalculationsEnabled(
        hDoc, FXJSE_Value_ToBoolean(hValue));
    return;
  }
  FX_BOOL bEnabled = pNotify->GetDocProvider()->IsCalculationsEnabled(hDoc);
  FXJSE_Value_SetBoolean(hValue, bEnabled);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_CurrentPage(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  if (bSetting) {
    pNotify->GetDocProvider()->SetCurrentPage(hDoc,
                                              FXJSE_Value_ToInteger(hValue));
    return;
  }
  int32_t iCurrentPage = pNotify->GetDocProvider()->GetCurrentPage(hDoc);
  FXJSE_Value_SetInteger(hValue, iCurrentPage);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Language(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_UNABLE_SET_LANGUAGE);
    return;
  }
  CFX_WideString wsLanguage;
  pNotify->GetAppProvider()->GetLanguage(wsLanguage);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsLanguage).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_NumPages(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_UNABLE_SET_NUMPAGES);
    return;
  }
  int32_t iNumPages = pNotify->GetDocProvider()->CountPages(hDoc);
  FXJSE_Value_SetInteger(hValue, iNumPages);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Platform(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_UNABLE_SET_PLATFORM);
    return;
  }
  CFX_WideString wsPlatform;
  pNotify->GetAppProvider()->GetPlatform(wsPlatform);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsPlatform).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Title(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  if (!m_pDocument->GetScriptContext()->IsRunAtClient()) {
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  if (bSetting) {
    CFX_ByteString bsValue;
    FXJSE_Value_ToUTF8String(hValue, bsValue);
    pNotify->GetDocProvider()->SetTitle(
        hDoc, CFX_WideString::FromUTF8(bsValue.AsStringC()));
    return;
  }
  CFX_WideString wsTitle;
  pNotify->GetDocProvider()->GetTitle(hDoc, wsTitle);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsTitle).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_ValidationsEnabled(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  if (bSetting) {
    pNotify->GetDocProvider()->SetValidationsEnabled(
        hDoc, FXJSE_Value_ToBoolean(hValue));
    return;
  }
  FX_BOOL bEnabled = pNotify->GetDocProvider()->IsValidationsEnabled(hDoc);
  FXJSE_Value_SetBoolean(hValue, bEnabled);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Variation(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  if (!m_pDocument->GetScriptContext()->IsRunAtClient()) {
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_UNABLE_SET_VARIATION);
    return;
  }
  CFX_WideString wsVariation;
  pNotify->GetAppProvider()->GetVariation(wsVariation);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsVariation).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Version(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_UNABLE_SET_VERSION);
    return;
  }
  CFX_WideString wsVersion;
  pNotify->GetAppProvider()->GetVersion(wsVersion);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsVersion).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_FoxitVersion(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_UNABLE_SET_VERSION);
    return;
  }
  CFX_WideString wsVersion;
  pNotify->GetAppProvider()->GetFoxitVersion(wsVersion);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsVersion).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Name(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_INVAlID_PROP_SET);
    return;
  }
  CFX_WideString wsAppName;
  pNotify->GetAppProvider()->GetAppName(wsAppName);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsAppName).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_FoxitName(
    FXJSE_HVALUE hValue,
    FX_BOOL bSetting,
    XFA_ATTRIBUTE eAttribute) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  if (bSetting) {
    ThrowScriptErrorMessage(XFA_IDS_INVAlID_PROP_SET);
    return;
  }
  CFX_WideString wsFoxitAppName;
  pNotify->GetAppProvider()->GetFoxitAppName(wsFoxitAppName);
  FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsFoxitAppName).AsStringC());
}
void CScript_HostPseudoModel::Script_HostPseudoModel_GotoURL(
    CFXJSE_Arguments* pArguments) {
  if (!m_pDocument->GetScriptContext()->IsRunAtClient()) {
    return;
  }
  int32_t iLength = pArguments->GetLength();
  if (iLength != 1) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"gotoURL");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  CFX_WideString wsURL;
  if (iLength >= 1) {
    CFX_ByteString bsURL = pArguments->GetUTF8String(0);
    wsURL = CFX_WideString::FromUTF8(bsURL.AsStringC());
  }
  pNotify->GetDocProvider()->GotoURL(hDoc, wsURL);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_OpenList(
    CFXJSE_Arguments* pArguments) {
  if (!m_pDocument->GetScriptContext()->IsRunAtClient()) {
    return;
  }
  int32_t iLength = pArguments->GetLength();
  if (iLength != 1) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"openList");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_Node* pNode = NULL;
  if (iLength >= 1) {
    FXJSE_HVALUE hValue = pArguments->GetValue(0);
    if (FXJSE_Value_IsObject(hValue)) {
      pNode = static_cast<CXFA_Node*>(FXJSE_Value_ToObject(hValue, nullptr));
    } else if (FXJSE_Value_IsUTF8String(hValue)) {
      CFX_ByteString bsString;
      FXJSE_Value_ToUTF8String(hValue, bsString);
      CFX_WideString wsExpression =
          CFX_WideString::FromUTF8(bsString.AsStringC());
      CXFA_ScriptContext* pScriptContext = m_pDocument->GetScriptContext();
      if (!pScriptContext) {
        FXJSE_Value_Release(hValue);
        return;
      }
      CXFA_Object* pObject = pScriptContext->GetThisObject();
      if (!pObject) {
        FXJSE_Value_Release(hValue);
        return;
      }
      uint32_t dwFlag = XFA_RESOLVENODE_Children | XFA_RESOLVENODE_Parent |
                        XFA_RESOLVENODE_Siblings;
      XFA_RESOLVENODE_RS resoveNodeRS;
      int32_t iRet = pScriptContext->ResolveObjects(
          pObject, wsExpression.AsStringC(), resoveNodeRS, dwFlag);
      if (iRet < 1 || !resoveNodeRS.nodes[0]->IsNode()) {
        FXJSE_Value_Release(hValue);
        return;
      }
      pNode = resoveNodeRS.nodes[0]->AsNode();
    }
    FXJSE_Value_Release(hValue);
  }
  CXFA_LayoutProcessor* pDocLayout = m_pDocument->GetDocLayout();
  if (!pDocLayout) {
    return;
  }
  CXFA_FFWidget* hWidget =
      pNotify->GetHWidget(pDocLayout->GetLayoutItem(pNode));
  if (!hWidget) {
    return;
  }
  pNotify->GetDocProvider()->SetFocusWidget(pNotify->GetHDOC(), hWidget);
  pNotify->OpenDropDownList(hWidget);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Response(
    CFXJSE_Arguments* pArguments) {
  int32_t iLength = pArguments->GetLength();
  if (iLength < 1 || iLength > 4) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"response");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CFX_WideString wsQuestion;
  CFX_WideString wsTitle;
  CFX_WideString wsDefaultAnswer;
  FX_BOOL bMark = FALSE;
  if (iLength >= 1) {
    CFX_ByteString bsQuestion = pArguments->GetUTF8String(0);
    wsQuestion = CFX_WideString::FromUTF8(bsQuestion.AsStringC());
  }
  if (iLength >= 2) {
    CFX_ByteString bsTitle = pArguments->GetUTF8String(1);
    wsTitle = CFX_WideString::FromUTF8(bsTitle.AsStringC());
  }
  if (iLength >= 3) {
    CFX_ByteString bsDefaultAnswer = pArguments->GetUTF8String(2);
    wsDefaultAnswer = CFX_WideString::FromUTF8(bsDefaultAnswer.AsStringC());
  }
  if (iLength >= 4) {
    bMark = pArguments->GetInt32(3) == 0 ? FALSE : TRUE;
  }
  CFX_WideString wsAnswer = pNotify->GetAppProvider()->Response(
      wsQuestion, wsTitle, wsDefaultAnswer, bMark);
  FXJSE_HVALUE hValue = pArguments->GetReturnValue();
  if (hValue) {
    FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsAnswer).AsStringC());
  }
}
void CScript_HostPseudoModel::Script_HostPseudoModel_DocumentInBatch(
    CFXJSE_Arguments* pArguments) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  int32_t iCur = pNotify->GetAppProvider()->GetCurDocumentInBatch();
  FXJSE_HVALUE hValue = pArguments->GetReturnValue();
  if (hValue) {
    FXJSE_Value_SetInteger(hValue, iCur);
  }
}
static int32_t XFA_FilterName(const CFX_WideStringC& wsExpression,
                              int32_t nStart,
                              CFX_WideString& wsFilter) {
  ASSERT(nStart > -1);
  int32_t iLength = wsExpression.GetLength();
  if (nStart >= iLength) {
    return iLength;
  }
  FX_WCHAR* pBuf = wsFilter.GetBuffer(iLength - nStart);
  int32_t nCount = 0;
  const FX_WCHAR* pSrc = wsExpression.c_str();
  FX_WCHAR wCur;
  while (nStart < iLength) {
    wCur = pSrc[nStart++];
    if (wCur == ',') {
      break;
    }
    pBuf[nCount++] = wCur;
  }
  wsFilter.ReleaseBuffer(nCount);
  wsFilter.TrimLeft();
  wsFilter.TrimRight();
  return nStart;
}
void CScript_HostPseudoModel::Script_HostPseudoModel_ResetData(
    CFXJSE_Arguments* pArguments) {
  int32_t iLength = pArguments->GetLength();
  if (iLength < 0 || iLength > 1) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"resetData");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CFX_WideString wsExpression;
  if (iLength >= 1) {
    CFX_ByteString bsExpression = pArguments->GetUTF8String(0);
    wsExpression = CFX_WideString::FromUTF8(bsExpression.AsStringC());
  }
  if (wsExpression.IsEmpty()) {
    pNotify->ResetData();
    return;
  }
  int32_t iStart = 0;
  CFX_WideString wsName;
  CXFA_Node* pNode = NULL;
  int32_t iExpLength = wsExpression.GetLength();
  while (iStart < iExpLength) {
    iStart = XFA_FilterName(wsExpression.AsStringC(), iStart, wsName);
    CXFA_ScriptContext* pScriptContext = m_pDocument->GetScriptContext();
    if (!pScriptContext) {
      return;
    }
    CXFA_Object* pObject = pScriptContext->GetThisObject();
    if (!pObject) {
      return;
    }
    uint32_t dwFlag = XFA_RESOLVENODE_Children | XFA_RESOLVENODE_Parent |
                      XFA_RESOLVENODE_Siblings;
    XFA_RESOLVENODE_RS resoveNodeRS;
    int32_t iRet = pScriptContext->ResolveObjects(pObject, wsName.AsStringC(),
                                                  resoveNodeRS, dwFlag);
    if (iRet < 1 || !resoveNodeRS.nodes[0]->IsNode()) {
      continue;
    }
    pNode = resoveNodeRS.nodes[0]->AsNode();
    pNotify->ResetData(pNode->GetWidgetData());
  }
  if (!pNode) {
    pNotify->ResetData();
  }
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Beep(
    CFXJSE_Arguments* pArguments) {
  if (!m_pDocument->GetScriptContext()->IsRunAtClient()) {
    return;
  }
  int32_t iLength = pArguments->GetLength();
  if (iLength < 0 || iLength > 1) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"beep");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  uint32_t dwType = 4;
  if (iLength >= 1) {
    dwType = pArguments->GetInt32(0);
  }
  pNotify->GetAppProvider()->Beep(dwType);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_SetFocus(
    CFXJSE_Arguments* pArguments) {
  if (!m_pDocument->GetScriptContext()->IsRunAtClient()) {
    return;
  }
  int32_t iLength = pArguments->GetLength();
  if (iLength != 1) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"setFocus");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_Node* pNode = NULL;
  if (iLength >= 1) {
    FXJSE_HVALUE hValue = pArguments->GetValue(0);
    if (FXJSE_Value_IsObject(hValue)) {
      pNode = static_cast<CXFA_Node*>(FXJSE_Value_ToObject(hValue, NULL));
    } else if (FXJSE_Value_IsUTF8String(hValue)) {
      CFX_ByteString bsString;
      FXJSE_Value_ToUTF8String(hValue, bsString);
      CFX_WideString wsExpression =
          CFX_WideString::FromUTF8(bsString.AsStringC());
      CXFA_ScriptContext* pScriptContext = m_pDocument->GetScriptContext();
      if (!pScriptContext) {
        FXJSE_Value_Release(hValue);
        return;
      }
      CXFA_Object* pObject = pScriptContext->GetThisObject();
      if (!pObject) {
        FXJSE_Value_Release(hValue);
        return;
      }
      uint32_t dwFlag = XFA_RESOLVENODE_Children | XFA_RESOLVENODE_Parent |
                        XFA_RESOLVENODE_Siblings;
      XFA_RESOLVENODE_RS resoveNodeRS;
      int32_t iRet = pScriptContext->ResolveObjects(
          pObject, wsExpression.AsStringC(), resoveNodeRS, dwFlag);
      if (iRet < 1 || !resoveNodeRS.nodes[0]->IsNode()) {
        FXJSE_Value_Release(hValue);
        return;
      }
      pNode = resoveNodeRS.nodes[0]->AsNode();
    }
    FXJSE_Value_Release(hValue);
  }
  pNotify->SetFocusWidgetNode(pNode);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_GetFocus(
    CFXJSE_Arguments* pArguments) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_Node* pNode = pNotify->GetFocusWidgetNode();
  if (!pNode) {
    return;
  }
  FXJSE_Value_Set(pArguments->GetReturnValue(),
                  m_pDocument->GetScriptContext()->GetJSValueFromMap(pNode));
}
void CScript_HostPseudoModel::Script_HostPseudoModel_MessageBox(
    CFXJSE_Arguments* pArguments) {
  if (!m_pDocument->GetScriptContext()->IsRunAtClient()) {
    return;
  }
  int32_t iLength = pArguments->GetLength();
  if (iLength < 1 || iLength > 4) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"messageBox");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CFX_WideString wsMessage;
  CFX_WideString bsTitle;
  uint32_t dwMessageType = XFA_MBICON_Error;
  uint32_t dwButtonType = XFA_MB_OK;
  if (iLength >= 1) {
    if (!Script_HostPseudoModel_ValidateArgsForMsg(pArguments, 0, wsMessage)) {
      return;
    }
  }
  if (iLength >= 2) {
    if (!Script_HostPseudoModel_ValidateArgsForMsg(pArguments, 1, bsTitle)) {
      return;
    }
  }
  if (iLength >= 3) {
    dwMessageType = pArguments->GetInt32(2);
    if (dwMessageType > XFA_MBICON_Status) {
      dwMessageType = XFA_MBICON_Error;
    }
  }
  if (iLength >= 4) {
    dwButtonType = pArguments->GetInt32(3);
    if (dwButtonType > XFA_MB_YesNoCancel) {
      dwButtonType = XFA_MB_OK;
    }
  }
  int32_t iValue = pNotify->GetAppProvider()->MsgBox(
      wsMessage, bsTitle, dwMessageType, dwButtonType);
  FXJSE_HVALUE hValue = pArguments->GetReturnValue();
  if (hValue) {
    FXJSE_Value_SetInteger(hValue, iValue);
  }
}
FX_BOOL CScript_HostPseudoModel::Script_HostPseudoModel_ValidateArgsForMsg(
    CFXJSE_Arguments* pArguments,
    int32_t iArgIndex,
    CFX_WideString& wsValue) {
  if (pArguments == NULL || iArgIndex < 0) {
    return FALSE;
  }
  FX_BOOL bIsJsType = FALSE;
  if (m_pDocument->GetScriptContext()->GetType() ==
      XFA_SCRIPTLANGTYPE_Javascript) {
    bIsJsType = TRUE;
  }
  FXJSE_HVALUE hValueArg = pArguments->GetValue(iArgIndex);
  if (!FXJSE_Value_IsUTF8String(hValueArg) && bIsJsType) {
    ThrowScriptErrorMessage(XFA_IDS_ARGUMENT_MISMATCH);
    FXJSE_Value_Release(hValueArg);
    return FALSE;
  }
  if (FXJSE_Value_IsNull(hValueArg)) {
    wsValue = FX_WSTRC(L"");
  } else {
    CFX_ByteString byMessage;
    FXJSE_Value_ToUTF8String(hValueArg, byMessage);
    wsValue = CFX_WideString::FromUTF8(byMessage.AsStringC());
  }
  FXJSE_Value_Release(hValueArg);
  return TRUE;
}
void CScript_HostPseudoModel::Script_HostPseudoModel_DocumentCountInBatch(
    CFXJSE_Arguments* pArguments) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  int32_t iValue = pNotify->GetAppProvider()->GetDocumentCountInBatch();
  FXJSE_HVALUE hValue = pArguments->GetReturnValue();
  if (hValue) {
    FXJSE_Value_SetInteger(hValue, iValue);
  }
}
void CScript_HostPseudoModel::Script_HostPseudoModel_Print(
    CFXJSE_Arguments* pArguments) {
  if (!m_pDocument->GetScriptContext()->IsRunAtClient()) {
    return;
  }
  int32_t iLength = pArguments->GetLength();
  if (iLength != 8) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"print");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  uint32_t dwOptions = 0;
  FX_BOOL bShowDialog = TRUE;
  if (iLength >= 1) {
    bShowDialog = pArguments->GetInt32(0) == 0 ? FALSE : TRUE;
  }
  if (bShowDialog) {
    dwOptions |= XFA_PRINTOPT_ShowDialog;
  }
  int32_t nStartPage = 0;
  if (iLength >= 2) {
    nStartPage = pArguments->GetInt32(1);
  }
  int32_t nEndPage = 0;
  if (iLength >= 3) {
    nEndPage = pArguments->GetInt32(2);
  }
  FX_BOOL bCanCancel = TRUE;
  if (iLength >= 4) {
    bCanCancel = pArguments->GetInt32(3) == 0 ? FALSE : TRUE;
  }
  if (bCanCancel) {
    dwOptions |= XFA_PRINTOPT_CanCancel;
  }
  FX_BOOL bShrinkPage = TRUE;
  if (iLength >= 5) {
    bShrinkPage = pArguments->GetInt32(4) == 0 ? FALSE : TRUE;
  }
  if (bShrinkPage) {
    dwOptions |= XFA_PRINTOPT_ShrinkPage;
  }
  FX_BOOL bAsImage = TRUE;
  if (iLength >= 6) {
    bAsImage = pArguments->GetInt32(5) == 0 ? FALSE : TRUE;
  }
  if (bAsImage) {
    dwOptions |= XFA_PRINTOPT_AsImage;
  }
  FX_BOOL bReverseOrder = TRUE;
  if (iLength >= 7) {
    bAsImage = pArguments->GetInt32(5) == 0 ? FALSE : TRUE;
  }
  bReverseOrder = pArguments->GetInt32(6) == 0 ? FALSE : TRUE;
  if (bReverseOrder) {
    dwOptions |= XFA_PRINTOPT_ReverseOrder;
  }
  FX_BOOL bPrintAnnot = TRUE;
  if (iLength >= 8) {
    bPrintAnnot = pArguments->GetInt32(7) == 0 ? FALSE : TRUE;
  }
  if (bPrintAnnot) {
    dwOptions |= XFA_PRINTOPT_PrintAnnot;
  }
  pNotify->GetDocProvider()->Print(hDoc, nStartPage, nEndPage, dwOptions);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_ImportData(
    CFXJSE_Arguments* pArguments) {
  int32_t iLength = pArguments->GetLength();
  if (iLength < 0 || iLength > 1) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"importData");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CFX_WideString wsFilePath;
  if (iLength > 0) {
    CFX_ByteString bsFilePath = pArguments->GetUTF8String(0);
    wsFilePath = CFX_WideString::FromUTF8(bsFilePath.AsStringC());
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  pNotify->GetDocProvider()->ImportData(hDoc, wsFilePath);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_ExportData(
    CFXJSE_Arguments* pArguments) {
  int32_t iLength = pArguments->GetLength();
  if (iLength < 0 || iLength > 2) {
    ThrowScriptErrorMessage(XFA_IDS_INCORRECT_NUMBER_OF_METHOD, L"exportData");
    return;
  }
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  CFX_WideString wsFilePath;
  FX_BOOL bXDP = TRUE;
  if (iLength >= 1) {
    CFX_ByteString bsFilePath = pArguments->GetUTF8String(0);
    wsFilePath = CFX_WideString::FromUTF8(bsFilePath.AsStringC());
  }
  if (iLength >= 2) {
    bXDP = pArguments->GetInt32(1) == 0 ? FALSE : TRUE;
  }
  pNotify->GetDocProvider()->ExportData(hDoc, wsFilePath, bXDP);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_PageUp(
    CFXJSE_Arguments* pArguments) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  int32_t nCurPage = pNotify->GetDocProvider()->GetCurrentPage(hDoc);
  int32_t nNewPage = 0;
  if (nCurPage <= 1) {
    return;
  }
  nNewPage = nCurPage - 1;
  pNotify->GetDocProvider()->SetCurrentPage(hDoc, nNewPage);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_PageDown(
    CFXJSE_Arguments* pArguments) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CXFA_FFDoc* hDoc = pNotify->GetHDOC();
  int32_t nCurPage = pNotify->GetDocProvider()->GetCurrentPage(hDoc);
  int32_t nPageCount = pNotify->GetDocProvider()->CountPages(hDoc);
  if (!nPageCount || nCurPage == nPageCount) {
    return;
  }
  int32_t nNewPage = 0;
  if (nCurPage >= nPageCount) {
    nNewPage = nPageCount - 1;
  } else {
    nNewPage = nCurPage + 1;
  }
  pNotify->GetDocProvider()->SetCurrentPage(hDoc, nNewPage);
}
void CScript_HostPseudoModel::Script_HostPseudoModel_CurrentDateTime(
    CFXJSE_Arguments* pArguments) {
  CXFA_FFNotify* pNotify = m_pDocument->GetParser()->GetNotify();
  if (!pNotify) {
    return;
  }
  CFX_WideString wsDataTime = pNotify->GetCurrentDateTime();
  FXJSE_HVALUE hValue = pArguments->GetReturnValue();
  if (hValue) {
    FXJSE_Value_SetUTF8String(hValue, FX_UTF8Encode(wsDataTime).AsStringC());
  }
}
