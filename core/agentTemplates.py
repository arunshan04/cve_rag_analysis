import os, re
from langchain_openai import AzureChatOpenAI
from langchain.embeddings import OllamaEmbeddings
from langchain.prompts import PromptTemplate
from langchain_community.chat_models import ChatOllama
from .utility import *
from .promptTemplates import *
from langchain_core.runnables import RunnableLambda
from typing import TypedDict
from langgraph.graph import StateGraph, END
import re
from elasticsearch import Elasticsearch



### Elasticsearch Configuration
from elasticsearch import Elasticsearch

client = Elasticsearch(
    "https://f0c40d3bde77471f83e6cace87537665.ap-southeast-1.aws.found.io",
    # api_key="Mk9odVlwY0JiN3JESEE4VzhkZ286WTNuZ29WR2pYMDF6em1DV193WVdkZw=="
    api_key="MnVpVVlwY0JiN3JESEE4V2FOaEk6X2NRRS1ESnM2V1A2TDJKQ25pb01NUQ=="
)

# llm = AzureChatOpenAI(azure_deployment=azure_openai_model_id, api_version=azure_openai_api_version,temperature=azure_openai_temperature)
llm = ChatOllama(model="llama3.2")

###----------------------------------------------
### - ProcessFlow Graph
###----------------------------------------------
class agent_dataType(TypedDict):
    input: str
    output: str
    pdf_pages: str

def create_processflow_graph():
    workflow = StateGraph(agent_dataType)

    workflow.add_node("router", routerAgent)
    workflow.add_node("ragTree", ragTreeAgent)
    workflow.add_node("rag", ragAgent)
    
    print('XX----------------------------------------------')
    workflow.add_conditional_edges(
        "router",
        lambda x: x["output"].split(",")[0].strip().lower(),
        {
            "tree": "ragTree",
            "general": "rag"
        }
    )

    workflow.set_entry_point("router")
    workflow.add_edge("ragTree", END)
    workflow.add_edge("rag", END)

    return workflow.compile()


def extract_cves(text):
    """
    Extract all CVE identifiers from a string.
    Example formats: CVE-2024-1234, CVE-2025-00001, etc.
    """
    cve_pattern = r'CVE-\d{4}-\d+'  # CVE-YYYY-NNNN to NNNNNNN
    return re.findall(cve_pattern, text.upper(), flags=re.IGNORECASE)

def processflow_graph_invoke(question):
    cves=extract_cves(question)
    if cves:
        print(f"Extracted CVEs: {cves}")
        question = f"Please provide details for the following CVEs: {', '.join(cves)}"
        cveDetails=search_by_cve_ids(cves)
        if cveDetails:
            print(f"CVE Details: {cveDetails}")
            question += f"\n\nCVE Details:\n{cveDetails}"
        else:
            print("No details found for the extracted CVEs.")
            question += "\n\nNo details found for the extracted CVEs."
    else:
        print("No CVEs found in the question.")
    processflow_graph = create_processflow_graph()
    print('Inside........ processflow_graph_invoke')
    return processflow_graph.invoke({"input": question})

###----------------------------------------------
### - Agent Template
###----------------------------------------------
def routerAgent(state):
    print('Inside routerAgent,,,,,,,')
    prompt = PromptTemplate.from_template(routerPrompt())
    chain = prompt | llm
    response = chain.invoke({"input": state["input"]})
    output = response.content.strip().lower()
    print(f"Router decision: {output}")
    print(f"Current State: {state} {output}")
    return {"input": state["input"], "output": output.strip("'\"")}

def ragTreeAgent(state):
    print('Inside ragTreeAgent,,,,,,,')
    # Get Entity Name from the User Input
    prompt = PromptTemplate.from_template(getEntityName())
    
    chain = (
        {"question": RunnableLambda(lambda x: state["input"])}
        | prompt
        | RunnableLambda(lambda x: (print(f"Prompt passed to LLM: {x}") if debug_mode else None) or x)
        | llm  
        )
    if debug_mode: print(f'Fetch Entity Name: {state["input"]}')
    
    parent_entity_response = chain.invoke({"question": state["input"]})
    
    print(f"parent_entity_response : {parent_entity_response.content}")
   
    # Fetch child entities for the Parent and Recursively loop the entities to get individual entity shareholder tree
    parent_entity, child_entities = fetch_all_child_entities(parent_entity_response.content)
    
    treePrompt = PromptTemplate.from_template(ragTreePrompt())
    
    treeContext=""
    for entity_name in child_entities:
        def query_func(params: dict) -> Dict:
            entity_name = params.get("entity_name")
            query = { 
            "query": { 
                "term": { "entity_name": entity_name }
            },
            #"_source": ["web_url", "pdf_url", "entity_name", "shareholders"],
            "_source": ["entity_name", "shareholders"],
            "sort": [{"page_number": {"order": "asc"}}]
            }
            return query
        
        chain = (
            {"context": getOrCreate_retriever(query_func)}
            | treePrompt
            | RunnableLambda(lambda x: (print(f"Prompt passed to LLM: {x}") if debug_mode else None) or x)
            | llm  
            )
        entity_response = chain.invoke({"entity_name" : entity_name})
        
        print(f"LLM Response: {entity_response.content}")
        
        if parent_entity==entity_name:
            print(f"Parent Entity Root Node")
            treeContext += "Root Node:\n" + entity_response.content
        else:
            print(f"Child Entity Child Node")
            treeContext += "\nChild Node:\n" + entity_response.content            
            
    print(f"treeContext: {treeContext}")
    
    # glue all the Tree using LLM
    treePrompt = PromptTemplate.from_template(ragTreeGlueNodePrompt())
    chain = (
        RunnableLambda(lambda _: {"context": treeContext}) 
        | treePrompt
        | RunnableLambda(lambda x: (print(f"Prompt passed to LLM: {x}") if debug_mode else None) or x)
        | llm  
        )
    
    response = chain.invoke({})
    if debug_mode: print(f"ragAgent Output: {response}")
    
    ### Fetch - PDF Pages
    pdf_pages = query_pdf_pages({'child_entities': child_entities})
    print(f"PDF-Pages: {pdf_pages}")

    output_content = response.content if hasattr(response, 'content') else response
    return {
        "output": output_content,  # Main response from LLM
        "pdf_pages": pdf_pages     # Separate response for PDF pages
    }


def ragAgent(state):
    print('Inside ragAgent,,,,,,,')
    prompt = PromptTemplate.from_template(ragPrompt())
    chain = (
        {"context": getOrCreate_retriever(semanting_search_on_shareholders) | format_docs,
         "question": RunnableLambda(lambda x: state["input"])}
        | prompt
        | RunnableLambda(lambda x: (print(f"Prompt passed to LLM: {x}") if debug_mode else None) or x)
        | llm  
        )
    if debug_mode: print(f'Rag input: {state["output"]}')
    response = chain.invoke({"search_query" : state["input"], "size" : 10})
    if debug_mode: print(f"ragAgent Output: {response}")
    output_content = response.content if hasattr(response, 'content') else response
    return {"output": output_content}