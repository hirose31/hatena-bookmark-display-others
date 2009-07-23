// ==UserScript==
// @name           HatenaBookmark import other services comments
// @include        http://b.hatena.ne.jp/entry/*
// @namespace      http://d.hatena.ne.jp/Sybian/
// @version        1.0.0
// ==/UserScript==

(function(){
// http://www.onicos.com/staff/iz/amuse/javascript/expert/

/* md5.js - MD5 Message-Digest
 * Copyright (C) 1999,2002 Masanao Izumo <iz@onicos.co.jp>
 * Version: 2.0.0
 * LastModified: May 13 2002
 *
 * This program is free software.  You can redistribute it and/or modify
 * it without any warranty.  This library calculates the MD5 based on RFC1321.
 * See RFC1321 for more information and algorism.
 */

/* Interface:
 * md5_128bits = MD5_hash(data);
 * md5_hexstr = MD5_hexhash(data);
 */

/* ChangeLog
 * 2002/05/13: Version 2.0.0 released
 * NOTICE: API is changed.
 * 2002/04/15: Bug fix about MD5 length.
 */


//    md5_T[i] = parseInt(Math.abs(Math.sin(i)) * 4294967296.0);
var MD5_T = new Array(0x00000000, 0xd76aa478, 0xe8c7b756, 0x242070db,
		      0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
		      0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1,
		      0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
		      0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51,
		      0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681,
		      0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87,
		      0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9,
		      0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
		      0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60,
		      0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085,
		      0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8,
		      0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7,
		      0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
		      0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314,
		      0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
		      0xeb86d391);

var MD5_round1 = new Array(new Array( 0, 7, 1), new Array( 1,12, 2),
			   new Array( 2,17, 3), new Array( 3,22, 4),
			   new Array( 4, 7, 5), new Array( 5,12, 6),
			   new Array( 6,17, 7), new Array( 7,22, 8),
			   new Array( 8, 7, 9), new Array( 9,12,10),
			   new Array(10,17,11), new Array(11,22,12),
			   new Array(12, 7,13), new Array(13,12,14),
			   new Array(14,17,15), new Array(15,22,16));

var MD5_round2 = new Array(new Array( 1, 5,17), new Array( 6, 9,18),
			   new Array(11,14,19), new Array( 0,20,20),
			   new Array( 5, 5,21), new Array(10, 9,22),
			   new Array(15,14,23), new Array( 4,20,24),
			   new Array( 9, 5,25), new Array(14, 9,26),
			   new Array( 3,14,27), new Array( 8,20,28),
			   new Array(13, 5,29), new Array( 2, 9,30),
			   new Array( 7,14,31), new Array(12,20,32));

var MD5_round3 = new Array(new Array( 5, 4,33), new Array( 8,11,34),
			   new Array(11,16,35), new Array(14,23,36),
			   new Array( 1, 4,37), new Array( 4,11,38),
			   new Array( 7,16,39), new Array(10,23,40),
			   new Array(13, 4,41), new Array( 0,11,42),
			   new Array( 3,16,43), new Array( 6,23,44),
			   new Array( 9, 4,45), new Array(12,11,46),
			   new Array(15,16,47), new Array( 2,23,48));

var MD5_round4 = new Array(new Array( 0, 6,49), new Array( 7,10,50),
			   new Array(14,15,51), new Array( 5,21,52),
			   new Array(12, 6,53), new Array( 3,10,54),
			   new Array(10,15,55), new Array( 1,21,56),
			   new Array( 8, 6,57), new Array(15,10,58),
			   new Array( 6,15,59), new Array(13,21,60),
			   new Array( 4, 6,61), new Array(11,10,62),
			   new Array( 2,15,63), new Array( 9,21,64));

function MD5_F(x, y, z) { return (x & y) | (~x & z); }
function MD5_G(x, y, z) { return (x & z) | (y & ~z); }
function MD5_H(x, y, z) { return x ^ y ^ z;          }
function MD5_I(x, y, z) { return y ^ (x | ~z);       }

var MD5_round = new Array(new Array(MD5_F, MD5_round1),
			  new Array(MD5_G, MD5_round2),
			  new Array(MD5_H, MD5_round3),
			  new Array(MD5_I, MD5_round4));

function MD5_pack(n32) {
  return String.fromCharCode(n32 & 0xff) +
	 String.fromCharCode((n32 >>> 8) & 0xff) +
	 String.fromCharCode((n32 >>> 16) & 0xff) +
	 String.fromCharCode((n32 >>> 24) & 0xff);
}

function MD5_unpack(s4) {
  return  s4.charCodeAt(0)        |
	 (s4.charCodeAt(1) <<  8) |
	 (s4.charCodeAt(2) << 16) |
	 (s4.charCodeAt(3) << 24);
}

function MD5_number(n) {
  while (n < 0)
    n += 4294967296;
  while (n > 4294967295)
    n -= 4294967296;
  return n;
}

function MD5_apply_round(x, s, f, abcd, r) {
  var a, b, c, d;
  var kk, ss, ii;
  var t, u;

  a = abcd[0];
  b = abcd[1];
  c = abcd[2];
  d = abcd[3];
  kk = r[0];
  ss = r[1];
  ii = r[2];

  u = f(s[b], s[c], s[d]);
  t = s[a] + u + x[kk] + MD5_T[ii];
  t = MD5_number(t);
  t = ((t<<ss) | (t>>>(32-ss)));
  t += s[b];
  s[a] = MD5_number(t);
}

function MD5_hash(data) {
  var abcd, x, state, s;
  var len, index, padLen, f, r;
  var i, j, k;
  var tmp;

  state = new Array(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);
  len = data.length;
  index = len & 0x3f;
  padLen = (index < 56) ? (56 - index) : (120 - index);
  if(padLen > 0) {
    data += "\x80";
    for(i = 0; i < padLen - 1; i++)
      data += "\x00";
  }
  data += MD5_pack(len * 8);
  data += MD5_pack(0);
  len  += padLen + 8;
  abcd = new Array(0, 1, 2, 3);
  x    = new Array(16);
  s    = new Array(4);

  for(k = 0; k < len; k += 64) {
    for(i = 0, j = k; i < 16; i++, j += 4) {
      x[i] = data.charCodeAt(j) |
	    (data.charCodeAt(j + 1) <<  8) |
	    (data.charCodeAt(j + 2) << 16) |
	    (data.charCodeAt(j + 3) << 24);
    }
    for(i = 0; i < 4; i++)
      s[i] = state[i];
    for(i = 0; i < 4; i++) {
      f = MD5_round[i][0];
      r = MD5_round[i][1];
      for(j = 0; j < 16; j++) {
	MD5_apply_round(x, s, f, abcd, r[j]);
	tmp = abcd[0];
	abcd[0] = abcd[3];
	abcd[3] = abcd[2];
	abcd[2] = abcd[1];
	abcd[1] = tmp;
      }
    }

    for(i = 0; i < 4; i++) {
      state[i] += s[i];
      state[i] = MD5_number(state[i]);
    }
  }

  return MD5_pack(state[0]) +
	 MD5_pack(state[1]) +
	 MD5_pack(state[2]) +
	 MD5_pack(state[3]);
}

function MD5_hexhash(data) {
    var i, out, c;
    var bit128;

    bit128 = MD5_hash(data);
    out = "";
    for(i = 0; i < 16; i++) {
	c = bit128.charCodeAt(i);
	out += "0123456789abcdef".charAt((c>>4) & 0xf);
	out += "0123456789abcdef".charAt(c & 0xf);
    }
    return out;
}

//------------------------------------------------------------
var JSONP={};
JSONP.YahooPipes={
	to_query: function(param){
		var q=[];
		for(var k in param){
			q.push([k,encodeURIComponent(param[k])].join("="));
		}
		return q.join("&");
	}
	,gen_url: function(param){
		param["_render"]="json";
		return "http://pipes.yahoo.com/pipes/pipe.run?"+this.to_query(param);
	}
	,page: function(param){
		param["_id"]="dd4c99a4116349eaa9e14500e5e434cd";
		var u=this.gen_url(param);
		return this.gen_url(param);
	}
	,feed: function(param){
		param["_id"]="2e0735392d2b5e7f46cf2d6da8183a29";
		var u=this.gen_url(param);
		return u;
	}
};

JSONP.registerCallback=function(prefix,fn){
	var w=(typeof unsafeWindow != "undefined")? unsafeWindow : window;
	var prefix=prefix || "callback";
	var fn=fn || function(){};
	var callback_name="sybian_callback_"+prefix;
	while(typeof w[callback_name] != "undefined"){
		callback_name+="_"+prefix;
	}
	w[callback_name]=fn;
	return callback_name;
}
JSONP.append=function(url){
	var script=document.createElement("script");
	script.setAttribute("src",url);
	script.setAttribute("charset","utf-8");
	document.body.appendChild(script);
	return script;
}


var Builder={}

Builder.tag=function(tag,url){
	return [
		'<a rel="tag" class="user-tag" href="',url,'">'
			,tag
		,'</a>'
	].join("")
}

// --------------------------------------------------
// separate comment/nocomment
// --------------------------------------------------

if(!document.getElementById("bookmarked_user")){
	document.getElementById("body").innerHTML+=[
		'<div class="info">'
			,'<ul id="bookmarked_user" class="bookmarklist">'
			,'</ul>'
		,'</div>'
	].join("");
}

var elmNocomment=document.createElement("ul");
elmNocomment.className="bookmarklist nocomment";
elmNocomment.setAttribute("style",[
		"background:#eef"
		,"padding:10px 0;"
		,"margin:10px 0;"
	].join(";")
);
var hasComment=function(li){
	var sp=li.getElementsByTagName("span");
	for(var i=0,len=sp.length; i<len; i++){
		if(sp[i].className == "comment"){
			return true;
		}
	}
	return false;
}
var li=document.getElementById("bookmarked_user").getElementsByTagName("li");
for(var i=0,len=li.length; i<len; i++){
	if(!hasComment(li[i])){
		elmNocomment.appendChild(li[i].cloneNode(true));
		li[i].style.display="none";
	}
}
document.getElementById("bookmarked_user").parentNode.appendChild(elmNocomment);


// --------------------------------------------------
// get external comments
// --------------------------------------------------

var url;
var matched;
if (matched = location.href.match(/^http:\/\/b.hatena.ne.jp\/entry\/s\/(.*)$/)) {
	url = "https://"+matched[1];
} else if (matched = location.href.match(/^http:\/\/b.hatena.ne.jp\/entry\/(.*)$/)) {
	url = "http://"+matched[1];
}

// var url_hash=MD5_hexhash(url);

var strings={
	nen: decodeURIComponent("%E5%B9%B4")
	,gatu: decodeURIComponent("%E6%9C%88")
	,hi: decodeURIComponent("%E6%97%A5")
}


function addComment(result){
	var ul=document.getElementById("bookmarked_user");
	for(var i=0,len=result.length; i<len; i++){
		var li=document.createElement("li");
		li.innerHTML=template(result[i]);
		ul.appendChild(li);
	}
}

function template(entry){
	return [
		'<img width="16" height="16" src="',entry.image,'" />'
		,' '
		,'<span class="timestamp">'
			,entry.date
		,'</span>'
		,' '
		,'<a href="',entry.url,'">'
			,'<img width="16" height="16" src="',entry.user_image,'" />'
		,'</a>'
		,' '
		,'<a href="',entry.url,'">',entry.user_name,'</a>'
		,' '
		,'<span class="user-tag">',entry.tags.join(", "),'</span>'
		,' '
		,'<span class="comment">',entry.comment,'</span>'
	].join("");
}

var Hacks={}

// Pookmark
Hacks["pookmark"]={};
JSONP.append(JSONP.YahooPipes.feed({
	url: "http://pookmark.jp/url/"+MD5_hexhash(url)+"/rss"
	,_callback: JSONP.registerCallback(
		"pookmark"
		,function(json){
			var posts=json.value.items,result=[];
			var hackCounter=0;
			for(var i=0,len=posts.length,post; post=posts[i],i<len; i++){
				if(post.description){
					post.url=post.link;
					post.comment=post.description;
					//post.user_image=post["foaf:topic"]["foaf:image"]["rdf:about"] || "";
					post.user_name=post.link.match(/[^/]*$/);
					post.user_image="http://image.jugemkey.jp/user/"+post.user_name+"/16";
					post.image="http://pookmark.jp/favicon.ico";
					post.tags=[];
					var tags=post["dc:subject"] || [];
					if(typeof tags == typeof "a"){
						tags=[tags];
					}
					(function(tags){
					for(var i=0,len=tags.length; i<len; i++){
						post.tags.push(Builder.tag(
							tags[i]
							,"http://pookmark.jp/user/"+post.user_name+"/"+tags[i]
						));
					}
					})(tags);
					with({post:post}){
						hackCounter++;
						window.setTimeout(function(){
							if(typeof Hacks["pookmark"][post.user_name] == "undefined"){
								setTimeout(arguments.callee,1000);
							}else{
								hackCounter--;
								post.date=Hacks["pookmark"][post.user_name]["date"];
								result.push(post);
							}
						},2000);
					}
				}
			}
			with({}){
				setTimeout(function(){
					if(hackCounter==0){
						addComment(result);
					}else{
						setTimeout(arguments.callee,1000);
					}
				},1000);
			}
		}
	)
}));


JSONP.append(JSONP.YahooPipes.page({
	url: "http://pookmark.jp/url/"+MD5_hexhash(url)
	,cut_from: '<div class="subsection" id="passenger-list">'
	,cut_to: '<div id="feed">'
	,split: '<li class="pt pt_s">'
	,_callback: JSONP.registerCallback(
		"pookmark"
		,function(page){
			var items=page.value.items
				,result=[]
				,dummy=document.createElement("noscript")
			;
			document.body.appendChild(dummy);
			items.shift();
			for(var i=0,len=items.length; i<len; i++){
				dummy.innerHTML=items[i].content||"";
				var c=document.evaluate('./span[not(@class)]',dummy,null,7,null);
				if(c.snapshotLength > 0){
					var post={};
					var tmp=document.evaluate('./span[@class="datetime"]',dummy,null,7,null).snapshotItem(0).innerHTML.split("/");
					post.url=document.evaluate('./a',dummy,null,7,null).snapshotItem(0).href;
					post.user_name=post.url.match(/[^/]*$/);
					Hacks["pookmark"][post.user_name]={};
					Hacks["pookmark"][post.user_name]["date"]=[tmp[0],strings.nen,tmp[1],strings.gatu,tmp[2],strings.hi].join("");
				}
			}
		}
	)
}));

// nifty clip
//JSONP.append(JSONP.YahooPipes.page({
//	url: "http://clip.nifty.com/entry/"+MD5_hexhash(url)
//	,cut_from: '<div class="comments">'
//	,cut_to: '<div class="kanren_clip_area">'
//	,_callback: JSONP.registerCallback(
//		"nifty"
//		,function(page){
//			opera.postError(page.count);
//		}
//	)
//}));

// delicious
JSONP.append(JSONP.YahooPipes.feed({
	url: "http://feeds.delicious.com/rss/url?url="+url
	,_callback: JSONP.registerCallback(
		"del"
		,function(feed){
			var items=feed.value.items||[],result=[];
			for(var i=0,len=items.length; i<len; i++){
				if(items[i].description){
					var item=items[i],post={};
					post.url=item.link;
					post.comment=item.description;
					var tmp=item["pubDate"].match(/^[0-9-]*/)[0].split("-");
					post.date=[tmp[0],strings.nen,tmp[1],strings.gatu,tmp[2],strings.hi].join("");
					post.user_name=item["dc:creator"];
					post.user_image=post.image="http://del.icio.us/favicon.ico";
					post.tags=(function(tags){
						for(var i=0,result=[],len=tags.length; i<len; i++){
							var tag=tags[i]["rdf:resource"];
							result.push(Builder.tag(
								tag.match(/[^/]*$/)
								,tag
							));
						}
						return result;
					})(item["taxo:topics"]["rdf:Bag"]["rdf:li"] || []);
					result.push(post);
				}
			}
			addComment(result);
		}
	)
}));

// Buzzurl
JSONP.append("http://api.buzzurl.jp/api/posts/get/v1/json/?url="+encodeURIComponent(url)+"&cb="+JSONP.registerCallback(
	"buzz"
	,function(json){
		if(!json[0]){
			return ;
		}
		var posts=json[0].posts,result=[];
		var nen=decodeURIComponent("%E5%B9%B4");
		var gatu=decodeURIComponent("%E6%9C%88");
		var hi=decodeURIComponent("%E6%97%A5");
		for(var i=0,len=posts.length; i<len; i++){
			if(posts[i].comment){
				posts[i].date=posts[i].date.replace(/([0-9]+)-([0-9]+)-([0-9]+)\s.*$/g,"$1"+nen+"$2"+gatu+"$3"+hi);
				posts[i].url="http://buzzurl.jp/user/"+posts[i].user_name;
				posts[i].user_image="http://buzzurl.jp/user/"+posts[i].user_name+"/photo";
				//posts[i].image="http://buzzurl.jp/favicon.ico";
				posts[i].image="http://cdn.buzzurl.jp/static/image/user/photo_default_small.gif";
				posts[i].tags=(function(post){
					if(!post.keywords) return [];
					var result=[],tags=post.keywords.split(",");
					for(var i=0,len=tags.length; i<len; i++){
						result.push(
							Builder.tag(tags[i],[post.url,'/keyword/',tags[i]].join(""))
						);
					}
					return result;
				})(posts[i]);
				result.push(posts[i]);
			}
		}
		addComment(result);

	}
));

// livedoor Clip
JSONP.append("http://api.clip.livedoor.com/json/comments?link="+encodeURIComponent(url)+"&callback="+JSONP.registerCallback(
	"ldc"
	,function(json){
		if(json.StatusCode != "200") return ;
		var posts=json.Comments,result=[];
		var myDate=new Date();
		myDate.getFormatted=function(){
			var m=this.getMonth()+1;
			var d=this.getDate();
			var nen=decodeURIComponent("%E5%B9%B4");
			var gatu=decodeURIComponent("%E6%9C%88");
			var hi=decodeURIComponent("%E6%97%A5");
			return this.getFullYear()+nen+((m<10) ? "0"+m : m)+gatu+((d < 10) ? "0"+d:d)+hi;
		}
		for(var i=0,len=posts.length; i<len; i++){
			if(!posts[i].notes){
				continue;
			}
			myDate.setTime(posts[i].created_on+"000");

			posts[i].user_name=posts[i].livedoor_id;
			posts[i].url="http://clip.livedoor.com/clips/"+posts[i].user_name;
			posts[i].tags=(function(post){
				var result=[],tags=post.tags;
				for(var i=0,len=tags.length; i<len; i++){
					result.push(
						Builder.tag(tags[i],post.url+"/tag/"+tags[i])
					);
				}
				return result;
			})(posts[i]);
			posts[i].date=myDate.getFormatted();
			posts[i].user_image="http://clip.livedoor.com/img/icon/user.gif";
			posts[i].image="http://clip.livedoor.com/favicon.ico";
			posts[i].comment=posts[i].notes;
			result.push(posts[i]);
		}
		addComment(result);
	}
));




})();
